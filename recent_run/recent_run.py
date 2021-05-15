from Registry import Registry
import struct
import sys
import codecs
from datetime import *
import re
import json
import yaml


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
                        "Program": guid_to_path(app_name),
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
                        "Program": guid_to_path(app_name),
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
    return utc_time.strftime("%A, %d %B, %Y %I:%M:%S %p UTC")


def guid_to_path(file_path):
    """Convert file path that has common Windows GUID to true path
    : Input: A file path (may contains Windows GUID)
    : Output: True file path"""

    # Dictionary of commond Windows GUIDs (Global Unique IDentifier)
    # retrieved from http://msdn.microsoft.com/en-us/library/bb882665.aspx
    common_guid = {
        "{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}": "AddNewPrograms",
        "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}": "AdminTools",
        "{A520A1A4-1780-4FF6-BD18-167343C5AF16}": "AppDataLow",
        "{A305CE99-F527-492B-8B1A-7E76FA98D6E4}": "AppUpdates",
        "{9E52AB10-F80D-49DF-ACB8-4330F5687855}": "CDBurning",
        "{DF7266AC-9274-4867-8D55-3BD661DE872D}": "ChangeRemovePrograms",
        "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": "CommonAdminTools",
        "{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}": "CommonOEMLinks",
        "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "CommonPrograms",
        "{A4115719-D62E-491D-AA7C-E74B8BE3B067}": "CommonStartMenu",
        "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}": "CommonStartup",
        "{B94237E7-57AC-4347-9151-B08C6C32D1F7}": "CommonTemplates",
        "{0AC0837C-BBF8-452A-850D-79D08E667CA7}": "Computer",
        "{4BFEFB45-347D-4006-A5BE-AC0CB0567192}": "Conflict",
        "{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}": "Connections",
        "{56784854-C6CB-462B-8169-88E350ACB882}": "Contacts",
        "{82A74AEB-AEB4-465C-A014-D097EE346D63}": "ControlPanel",
        "{2B0F765D-C0E9-4171-908E-08A611B84FF6}": "Cookies",
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
        "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
        "{1777F761-68AD-4D8A-87BD-30B759FA33DD}": "Favorites",
        "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}": "Fonts",
        "{CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434}": "Games",
        "{054FAE61-4DD8-4787-80B6-090220C4B700}": "GameTasks",
        "{D9DC8A3B-B784-432E-A781-5A1130A75963}": "History",
        "{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}": "Internet",
        "{352481E8-33BE-4251-BA85-6007CAEDCF9D}": "InternetCache",
        "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}": "Links",
        "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "LocalAppData",
        "{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}": "LocalizedResourcesDir",
        "{4BD8D571-6D19-48D3-BE97-422220080E43}": "Music",
        "{C5ABBF53-E17F-4121-8900-86626FC2C973}": "NetHood",
        "{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}": "Network",
        "{2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39}": "OriginalImages",
        "{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}": "PhotoAlbums",
        "{33E28130-4E1E-4676-835A-98395C3BC3BB}": "Pictures",
        "{DE92C1C7-837F-4F69-A3BB-86E631204A23}": "Playlists",
        "{76FC4E2D-D6AD-4519-A663-37BD56068185}": "Printers",
        "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}": "PrintHood",
        "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "Profile",
        "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "ProgramData",
        "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "ProgramFiles",
        "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": "ProgramFilesCommon",
        "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": "ProgramFilesCommonX64",
        "{DE974D24-D9C6-4D3E-BF91-F4455120B917}": "ProgramFilesCommonX86",
        "{6D809377-6AF0-444B-8957-A3773F02200E}": "ProgramFilesX64",
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "ProgramFilesX86",
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "Programs",
        "{DFDF76A2-C82A-4D63-906A-5644AC457385}": "Public",
        "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "PublicDesktop",
        "{ED4824AF-DCE4-45A8-81E2-FC7965083634}": "PublicDocuments",
        "{3D644C9B-1FB8-4F30-9B45-F670235F79C0}": "PublicDownloads",
        "{DEBF2536-E1A8-4C59-B6A2-414586476AEA}": "PublicGameTasks",
        "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": "PublicMusic",
        "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": "PublicPictures",
        "{2400183A-6185-49FB-A2D8-4A392A602BA3}": "PublicVideos",
        "{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}": "QuickLaunch",
        "{AE50C081-EBD2-438A-8655-8A092E34987A}": "Recent",
        "{BD85E001-112E-431E-983B-7B15AC09FFF1}": "RecordedTV",
        "{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}": "RecycleBin",
        "{8AD10C31-2ADB-4296-A8F7-E4701232C972}": "ResourceDir",
        "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "RoamingAppData",
        "{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}": "SampleMusic",
        "{C4900540-2379-4C75-844B-64E6FAF8716B}": "SamplePictures",
        "{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}": "SamplePlaylists",
        "{859EAD94-2E85-48AD-A71A-0969CB56A6CD}": "SampleVideos",
        "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}": "SavedGames",
        "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}": "SavedSearches",
        "{EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E}": "SEARCH_CSC",
        "{98EC0E18-2098-4D44-8644-66979315A281}": "SEARCH_MAPI",
        "{190337D1-B8CA-4121-A639-6D472D16972A}": "SearchHome",
        "{8983036C-27C0-404B-8F08-102D10DCFD74}": "SendTo",
        "{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}": "SidebarDefaultParts",
        "{A75D362E-50FC-4FB7-AC2C-A8BEAA314493}": "SidebarParts",
        "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": "StartMenu",
        "{B97D20BB-F46A-4C97-BA10-5E3608430854}": "Startup",
        "{43668BF8-C14E-49B2-97C9-747784D784B7}": "SyncManager",
        "{289A9A43-BE44-4057-A41B-587A76D7E7F9}": "SyncResults",
        "{0F214138-B1D3-4A90-BBA9-27CBC0C5389A}": "SyncSetup",
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "System",
        "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "SystemX86",
        "{A63293E8-664E-48DB-A079-DF759E0509F7}": "Templates",
        "{5B3749AD-B49F-49C1-83EB-15370FBD4882}": "TreeProperties",
        "{0762D272-C50A-4BB0-A382-697DCD729B80}": "UserProfiles",
        "{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}": "UsersFiles",
        "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "Videos",
        "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "Windows"
    }

    # Compile a regex to search for common GUID in file path which usually inside {}
    guid = re.compile(r"({.*})")
    current_guid = guid.search(file_path)

    # If a match is found and the found GUID is in the common_guid dictionary
    # -> replace the GUID with its name in the commond_guid dictionary
    if current_guid and current_guid.group(1) in common_guid:
        return file_path.replace(current_guid.group(1), common_guid[current_guid.group(1)])
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
            "Enter your output file's name (allowed extension: .json, .yaml): ")

        # If user does not specify an extension -> Use json as default
        if len(file_name.split(".")) < 2:
            print("[*] File extension is not specified! Using \".json\"")
            file_name = "{}.json".format(file_name)
            json_writer(file_name, recent_run)
            print("[+] Successfully write to {}".format(file_name))

        # Else extract the extension and see if it match json or yaml
        else:
            ext = file_name.split(".")[-1]
            while ext != "json" and ext != "yaml":
                print("[-] Only .json and .yaml extension is allowed! Try again!")
                file_name = input(
                    "Enter your output file's name (allowed extension: .json, .yaml): ")
                ext = file_name.split(".")[-1]
            if ext == "json":
                json_writer(file_name, recent_run)
            elif ext == "yaml":
                yaml_writer(file_name, recent_run)
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
