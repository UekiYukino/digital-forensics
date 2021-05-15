from Registry import Registry
import struct
import sys
import codecs
from datetime import *
import re
import json
import yaml
import csv


def process_hive(registry_hive):
    """Parse registry hive's UserAssist key to retrieve information of recent run programs
    : Input: Path to the registry hive
    : Output: A list containing multiple dictionary of recent run programs information
    """
    # Try to open the registry hive and capture the errrors
    try:
        reg = Registry.Registry(registry_hive)
    except Registry.RegistryParse.ParseException:
        print("[-] Invalid Registry!")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] {} could not be found!".format(registry_hive))
        sys.exit(1)

    # Locate the UserAssist key inside the registry hive -> Exit and return error message if the hive does not contain UserAssist
    try:
        ua_key = reg.open(
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    except Registry.RegistryKeyNotFoundException:
        print("[-] UserAssist Key could not be found in the Registry hive!")
        sys.exit(1)

    # Initialize a list to store parsed values
    apps_list = []

    # UserAssist key structures:
    # UserAssist
    # |__ Subkeys
    #     |__ Count
    #          |___ names (Rot-13 encoded) : binary values
    # Iterate through the subkeys of UserAssist key

    for ua_subkey in ua_key.subkeys():

        # Check if the subkey of the UserAssist subkey contains "Count"
        # Then Extract for only the subkey that has value different than 0
        if ua_subkey.subkey("Count") and ua_subkey.subkey("Count").values_number() != 0:
            # Empty the app dictionary for each subkey found
            app = {}

            # Iterate through the information inside the Count subkey to extract application name and theirs registry values
            for program in ua_subkey.subkey("Count").values():
                # Decode the key's name using rot13
                app_name = codecs.decode(program.name(), "rot13")

                # Add the program name with its raw data to the app dictionary
                app[app_name] = program.raw_data()
            # Add the current value of the app dictionary to apps_list
            apps_list.append(app)
    return apps_list


def parse_value(apps_list):
    """Parse binary part of the registry to readable integer information
    : Input: List of multiple dictionaries with binary string as the value
    : Output: List of multiple dictionaries with informative data as values"""

    # Dictionary of commond Windows GUIDs (Global Unique IDentifier)
    # retrieved from https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid
    common_guid = {
        "{008CA0B1-55B4-4C56-B8A8-4DE4B299D3BE}": "%APPDATA%\\Microsoft\\Windows\\AccountPictures",
        "{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}": "Get Programs",
        "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
        "{B2C5E279-7ADD-439F-B28C-C41FE1BBF672}": "%LOCALAPPDATA%\\Desktop",
        "{7BE16610-1F7F-44AC-BFF0-83E15F2FFCA1}": "%LOCALAPPDATA%\\Documents",
        "{7CFBEFBC-DE1F-45AA-B843-A542AC536CC9}": "%LOCALAPPDATA%\\Favorites",
        "{559D40A3-A036-40FA-AF61-84CB430A4D34}": "%LOCALAPPDATA%\\ProgramData",
        "{A3918781-E5F2-4890-B3D9-A7E54332328C}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Application Shortcuts",
        "{1E87508D-89C2-42F0-8A7E-645A0F50CA58}": "Applications",
        "{A305CE99-F527-492B-8B1A-7E76FA98D6E4}": "Installed Updates",
        "{AB5FB87B-7CE2-4F83-915D-550846C9537B}": "%USERPROFILE%\\Pictures\\Camera Roll",
        "{9E52AB10-F80D-49DF-ACB8-4330F5687855}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn",
        "{DF7266AC-9274-4867-8D55-3BD661DE872D}": "Programs and Features",
        "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
        "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}": "%ALLUSERSPROFILE%\\OEM Links",
        "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs",
        "{A4115719-D62E-491D-AA7C-E74B8BE3B067}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu",
        "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        "{B94237E7-57AC-4347-9151-B08C6C32D1F7}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Templates",
        "{0AC0837C-BBF8-452A-850D-79D08E667CA7}": "Computer",
        "{4BFEFB45-347D-4006-A5BE-AC0CB0567192}": "Conflicts",
        "{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}": "Network Connections",
        "{56784854-C6CB-462B-8169-88E350ACB882}": "%USERPROFILE%\\Contacts",
        "{82A74AEB-AEB4-465C-A014-D097EE346D63}": "Control Panel",
        "{2B0F765D-C0E9-4171-908E-08A611B84FF6}": "%APPDATA%\\Microsoft\\Windows\\Cookies",
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%USERPROFILE%\\Desktop",
        "{5CE4A5E9-E4EB-479D-B89F-130C02886155}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\DeviceMetadataStore",
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%USERPROFILE%\\Documents",
        "{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Documents.library-ms",
        "{374DE290-123F-4565-9164-39C4925E467B}": "%USERPROFILE%\\Downloads",
        "{1777F761-68AD-4D8A-87BD-30B759FA33DD}": "%USERPROFILE%\\Favorites",
        "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}": "%windir%\\Fonts",
        "{CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434}": "Games",
        "{054FAE61-4DD8-4787-80B6-090220C4B700}": "%LOCALAPPDATA%\\Microsoft\\Windows\\GameExplorer",
        "{D9DC8A3B-B784-432E-A781-5A1130A75963}": "%LOCALAPPDATA%\\Microsoft\\Windows\\History",
        "{52528A6B-B9E3-4ADD-B60D-588C2DBA842D}": "Homegroup",
        "{9B74B6A3-0DFD-4F11-9E78-5F7800F2E772}": "%USERNAME%",
        "{BCB5256F-79F6-4CEE-B725-DC34E402FD46}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\ImplicitAppShortcuts",
        "{352481E8-33BE-4251-BA85-6007CAEDCF9D}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files",
        "{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}": "The Internet",
        "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}": "%APPDATA%\\Microsoft\\Windows\\Libraries",
        "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}": "%USERPROFILE%\\Links",
        "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "%USERPROFILE%\\AppData\\Local",
        "{A520A1A4-1780-4FF6-BD18-167343C5AF16}": "%USERPROFILE%\\AppData\\Local",
        "{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}": "%windir%\\resources\\0409 (code page)",
        "{4BD8D571-6D19-48D3-BE97-422220080E43}": "%USERPROFILE%\\Music",
        "{2112AB0A-C86A-4FFE-A368-0DE96E47012E}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Music.library-ms",
        "{C5ABBF53-E17F-4121-8900-86626FC2C973}": "%APPDATA%\\Microsoft\\Windows\\Network Shortcuts",
        "{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}": "Network",
        "{31C0DD25-9439-4F12-BF41-7FF4EDA38722}": "%USERPROFILE%\\3D Objects",
        "{2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39}": "%LOCALAPPDATA%\\Microsoft\\Windows Photo Gallery\\Original Images",
        "{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}": "%USERPROFILE%\\Pictures\\Slide Shows",
        "{A990AE9F-A03B-4E80-94BC-9912D7504104}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Pictures.library-ms",
        "{33E28130-4E1E-4676-835A-98395C3BC3BB}": "%USERPROFILE%\\Pictures",
        "{DE92C1C7-837F-4F69-A3BB-86E631204A23}": "%USERPROFILE%\\Music\\Playlists",
        "{76FC4E2D-D6AD-4519-A663-37BD56068185}": "Printers",
        "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}": "%APPDATA%\\Microsoft\\Windows\\Printer Shortcuts",
        "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "%SystemDrive%\\Users\\%USERNAME%",
        "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "%SystemDrive%\\ProgramData",
        "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "%SystemDrive%\\Program Files",
        "{6D809377-6AF0-444B-8957-A3773F02200E}": "%SystemDrive%\\Program Files",
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%SystemDrive%\\Program Files",
        "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": "%ProgramFiles%\\Common Files",
        "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": "%ProgramFiles%\\Common Files",
        "{DE974D24-D9C6-4D3E-BF91-F4455120B917}": "%ProgramFiles%\\Common Files",
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
        "{DFDF76A2-C82A-4D63-906A-5644AC457385}": "%SystemDrive%\\Users\\Public",
        "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "%PUBLIC%\\Desktop",
        "{ED4824AF-DCE4-45A8-81E2-FC7965083634}": "%PUBLIC%\\Documents",
        "{3D644C9B-1FB8-4F30-9B45-F670235F79C0}": "%PUBLIC%\\Downloads",
        "{DEBF2536-E1A8-4C59-B6A2-414586476AEA}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\GameExplorer",
        "{48DAF80B-E6CF-4F4E-B800-0E69D84EE384}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Libraries",
        "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": "%PUBLIC%\\Music",
        "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": "%PUBLIC%\\Pictures",
        "{E555AB60-153B-4D17-9F04-A5FE99FC15EC}": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Ringtones",
        "{0482AF6C-08F1-4C34-8C90-E17EC98B1E17}": "%PUBLIC%\\AccountPictures",
        "{2400183A-6185-49FB-A2D8-4A392A602BA3}": "%PUBLIC%\\Videos",
        "{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch",
        "{AE50C081-EBD2-438A-8655-8A092E34987A}": "%APPDATA%\\Microsoft\\Windows\\Recent",
        "{1A6FDBA2-F42D-4358-A798-B74D745926C5}": "%PUBLIC%\\RecordedTV.library-ms",
        "{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}": "Recycle Bin",
        "{8AD10C31-2ADB-4296-A8F7-E4701232C972}": "%windir%\\Resources",
        "{C870044B-F49E-4126-A9C3-B52A1FF411E8}": "%LOCALAPPDATA%\\Microsoft\\Windows\\Ringtones",
        "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "%USERPROFILE%\\AppData\\Roaming",
        "{AAA8D5A5-F1D6-4259-BAA8-78E7EF60835E}": "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamedTileImages",
        "{00BCFC5A-ED94-4E48-96A1-3F6217F21990}": "%LOCALAPPDATA%\\Microsoft\\Windows\\RoamingTiles",
        "{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}": "%PUBLIC%\\Music\\Sample Music",
        "{C4900540-2379-4C75-844B-64E6FAF8716B}": "%PUBLIC%\\Pictures\\Sample Pictures",
        "{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}": "%PUBLIC%\\Music\\Sample Playlists",
        "{859EAD94-2E85-48AD-A71A-0969CB56A6CD}": "%PUBLIC%\\Videos\\Sample Videos",
        "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}": "%USERPROFILE%\\Saved Games",
        "{3B193882-D3AD-4EAB-965A-69829D1FB59F}": "%USERPROFILE%\\Pictures\\Saved Pictures",
        "{E25B5812-BE88-4BD9-94B0-29233477B6C3}": "%APPDATE%\\Microsoft\\Windows\\Libraries\\SavedPictures.library-ms",
        "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}": "%USERPROFILE%\\Searches",
        "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}": "%USERPROFILE%\\Pictures\\Screenshots",
        "{EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E}": "Offline Files",
        "{0D4C3DB6-03A3-462F-A0E6-08924C41B5D4}": "%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\History",
        "{190337D1-B8CA-4121-A639-6D472D16972A}": "Search Results",
        "{98EC0E18-2098-4D44-8644-66979315A281}": "Microsoft Office Outlook",
        "{7E636BFE-DFA9-4D5E-B456-D7B39851D8A9}": "%LOCALAPPDATA%\\Microsoft\\Windows\\ConnectedSearch\\Templates",
        "{8983036C-27C0-404B-8F08-102D10DCFD74}": "%APPDATA%\\Microsoft\\Windows\\SendTo",
        "{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}": "%ProgramFiles%\\Windows Sidebar\\Gadgets",
        "{A75D362E-50FC-4FB7-AC2C-A8BEAA314493}": "%LOCALAPPDATA%\\Microsoft\\Windows Sidebar\\Gadgets",
        "{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}": "%USERPROFILE%\\OneDrive",
        "{767E6811-49CB-4273-87C2-20F355E1085B}": "%USERPROFILE%\\OneDrive\\Pictures\\Camera Roll",
        "{24D89E24-2F19-4534-9DDE-6A6671FBB8FE}": "%USERPROFILE%\\OneDrive\\Documents",
        "{339719B5-8C47-4894-94C2-D8F77ADD44A6}": "%USERPROFILE%\\OneDrive\\Pictures",
        "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": "%APPDATA%\\Microsoft\\Windows\\Start Menu",
        "{B97D20BB-F46A-4C97-BA10-5E3608430854}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        "{43668BF8-C14E-49B2-97C9-747784D784B7}": "Sync Center",
        "{289A9A43-BE44-4057-A41B-587A76D7E7F9}": "Sync Results",
        "{0F214138-B1D3-4A90-BBA9-27CBC0C5389A}": "Sync Setup",
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%windir%\\system32",
        "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "%windir%\\system32",
        "{A63293E8-664E-48DB-A079-DF759E0509F7}": "%APPDATA%\\Microsoft\\Windows\\Templates",
        "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
        "{0762D272-C50A-4BB0-A382-697DCD729B80}": "%SystemDrive%\\Users",
        "{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}": "%LOCALAPPDATA%\\Programs",
        "{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}": "%LOCALAPPDATA%\\Programs\\Common",
        "{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}": "[User Full Name]",
        "{A302545D-DEFF-464B-ABE8-61C8648D939B}": "Libraries",
        "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "%USERPROFILE%\\Videos",
        "{491E922F-5643-4AF4-A7EB-4E7A138D8174}": "%APPDATA%\\Microsoft\\Windows\\Libraries\\Videos.library-ms",
        "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%windir%"
    }

    # Declare Windows Folder ID to map system path
    win7 = {
        "%ALLUSERSPROFILE%": "C:\\ProgramData",
        "%APPDATA%": "C:\\Users\\username\\AppData\\Roaming",
        "%LOCALAPPDATA%": "C:\\Users\\username\\AppData\\Local",
        "%ProgramData%": "C:\\ProgramData",
        "%ProgramFiles%": "C:\\Program Files",
        "%ProgramFiles(x86)%": "C:\\Program Files (x86)",
        "%PUBLIC%": "C:\\Users\\Public",
        "%SystemDrive%": "C:",
        "%USERPROFILE%": "C:\\Users\\username",
        "%windir%": "C:\\Windows"
    }

    winXP = {
        "%ALLUSERSPROFILE%": "C:\\Documents and Settings\\All Users",
        "%APPDATA%": "C:\\Documents and Settings\\username\\Application Data",
        "%ProgramFiles%": "C:\\Program Files",
        "%SystemDrive%": "C:",
        "%USERPROFILE%": "C:\\Documents and Settings\\username",
        "%windir%": "C:\\Windows"
    }

    parsed_app_list = []
    for app in apps_list:
        for app_name, bin_value in app.items():

            # Only unpack values with length equal to 16 (WinXP) or 72 (Win7 and above)
            # There will also keys like UEME_CTLSESSION which has value different from 16 and 72 but does not store info about execution programs
            if len(bin_value) == 16:
                # 16 bytes structure of WinXP keys value
                # Session ID:   4 bytes (0-3)       Integer
                # Count:        4 bytes (4-7)       Integer
                # File Time:    8 bytes (8-15)      Interger
                # -> Unpack using:
                #       + 2 - 4 bytes integer (2i)
                #       + 1 - 8 bytes integer (q)
                raw = struct.unpack("<2iq", bin_value)
                parsed_app_list.append(
                    {
                        "Program": guid_to_path(app_name, common_guid, winXP),
                        "Session ID": raw[0],
                        "Used Count": raw[1],
                        "Last Access (UTC)": filetime_to_utc(raw[2]),
                        "Focus Time (ms)": "N/A",
                        "Focus Count": "N/A"
                    })
            elif len(bin_value) == 72:
                # 64 bytes structure of Win7 keys value
                # Session ID:   4 bytes (0-3)       Integer
                # Count:        4 bytes (4-7)       Integer
                # Focus Count:  4 bytes (8-11)      Integer
                # Focus Time:   4 bytes (12-15)     Integer
                # Padding:      44 bytes (16-59)    N/A
                # File Time:    8 bytes (60-67)     Integer
                # Padding:      4 bytes (68-71)     N/A
                # -> Unpack using:
                #       + 4 - 4 bytes integer (4i)
                #       + 44 - 1 byte x value (44x)
                #       + 1 - 8 bytes integer (q)
                #       + 4 - 1 byte x value (4x)
                raw = struct.unpack("<4i44xq4x", bin_value)
                parsed_app_list.append(
                    {
                        "Program": guid_to_path(app_name, common_guid, win7),
                        "Session ID": raw[0],
                        "Used Count": raw[1],
                        "Last Access (UTC)": filetime_to_utc(raw[4]),
                        "Focus Time (ms)": raw[2],
                        "Focus Count": raw[3]
                    })
            else:
                continue
    return parsed_app_list


def filetime_to_utc(filetime):
    """Convert a Filetime object to UTC time
    : Input: Windows Filetime
    : Output: Time in UTC"""
    # Return N/A if the file time is 0
    if filetime == 0:
        return "N/A"
    # Filetime object represent the count of 100 nanoseconds since 01/01/1601
    # Time delta is going to calculate the time that the filetime string represent
    # Then add those time to the datetime of 01/01/1601
    utc_time = datetime(1601, 1, 1) + timedelta(microseconds=filetime/10)
    return utc_time.strftime("%d %B, %Y %I:%M:%S %p UTC")


def guid_to_path(file_path, common_guid, win_path):
    """Convert file path that has common Windows GUID to true path
    : Input: A file path (may contains Windows GUID), dictionary of common GUID
    : Output: True file path"""

    # Compile a regex to search for common GUID in file path which usually inside {}
    guid = re.compile(r"({.*})")
    current_guid = guid.search(file_path)

    # If a match is found and the found GUID is in the common_guid dictionary
    # -> replace the GUID with its name in the commond_guid dictionary
    if current_guid and current_guid.group(1) in common_guid:
        # Return the system path (E.g: %APPDATA%)
        system_path = file_path.replace(current_guid.group(
            1), common_guid[current_guid.group(1)])

        # USe regex to extract the system path part of the file
        folder_id = re.compile(r"(%.*%)")
        current_folder_id = folder_id.search(system_path)

        # If a match is found, replace that part with the corresponding true path found in win_path dictionary
        if current_folder_id and current_folder_id.group(1) in win_path:
            return system_path.replace(current_folder_id.group(
                1), win_path[current_folder_id.group(1)])
        else:
            return system_path

    # Else: Only return the file path
    else:
        return file_path


def json_writer(file_name, content):
    """Write output to json file"""
    with open(file_name, "w") as json_file:
        json.dump(content, json_file, indent=3)


def yaml_writer(file_name, content):
    """Write output to yaml file"""
    with open(file_name, "w") as yaml_file:
        yaml.dump(content, yaml_file, indent=3)


def csv_writer(file_name, content):
    """Write output to csv file"""
    headers = list(content[0].keys())
    program_list = []
    # Iterate over the content dictionary and append the value to the program list
    for program in content:
        program_list.append([program[header] for header in headers])
    # Open the file and write to it, newline ="" is to prevent writing an empty line between values
    with open(file_name, "w", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)
        # Write the header on first line
        csv_writer.writerow(headers)

        # Write content of the program_list as content in the file
        csv_writer.writerows(program_list)


def main():
    hive = input("Enter the path to your NTUSER.DAT file: ")

    processed_hive = process_hive(hive)
    recent_run = parse_value(processed_hive)

    # Prompt user if they want to write to a file or not
    write_to_file = input("Do you want to write the output to a file? (y/n) ")
    while write_to_file.lower() != "y" and write_to_file.lower() != "n":
        print("[-] Only (y/n) is accepted! Try again!")
        write_to_file = input(
            "Do you want to write the output to a file? (y/n) ")

    if write_to_file == "y":
        file_name = input(
            "Enter your output file's name (allowed extension: .json, .yaml, .csv): ")

        # If user does not specify an extension -> Use json as default
        if len(file_name.split(".")) < 2:
            print("[*] File extension is not specified! Using \".csv\"")
            file_name = "{}.csv".format(file_name)
            csv_writer(file_name, recent_run)
            print("[+] Successfully write to {}".format(file_name))

        # Else extract the extension and see if it match json, yaml or csv
        else:
            ext = file_name.split(".")[-1]
            while ext != "json" and ext != "yaml" and ext != "csv":
                print("[-] Only .json and .yaml extension is allowed! Try again!")
                file_name = input(
                    "Enter your output file's name (allowed extension: .json, .yaml): ")
                ext = file_name.split(".")[-1]
            if ext == "json":
                json_writer(file_name, recent_run)
            elif ext == "yaml":
                yaml_writer(file_name, recent_run)
            elif ext == "csv":
                csv_writer(file_name, recent_run)
            print("[+] Successfully write to {}".format(file_name))

    # If the user does not want output to a file -> print the output to the command prompt
    else:
        # Iterate through the list then print out the result
        for program in recent_run:
            print("{:=^50}".format(""))
            for header, info in program.items():
                print("{}: {}".format(header, info))


if __name__ == "__main__":
    main()
