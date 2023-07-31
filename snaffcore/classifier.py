import re
import toml
import os
import logging
# import pprint
import termcolor

from impacket.smbconnection import SessionError, SMBConnection
from .smb import *
from .file import *

log = logging.getLogger('snafflepy.classifier')

# TODO


class Rules:        

    def __init__(self) -> None:
        self.classifier_rules = []
        self.share_classifiers = []
        self.directory_classifiers = []
        self.file_classifiers = []
        self.contents_classifiers = []
        self.postmatch_classifiers = []

    def prepare_classifiers(self):
        share_path = "./snaffcore/DefaultRules/"

        for root, dirs, files in os.walk(share_path, topdown=False):
            for name in files:
                # print(os.path.join(root,name))
                with open(os.path.join(root, name), 'r') as tfile:
                    toml_loaded = toml.load(tfile)
                for dict_rule in toml_loaded['ClassifierRules']:
                    if dict_rule['EnumerationScope'] == "ShareEnumeration":
                        self.share_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "FileEnumeration":
                        self.file_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "DirectoryEnumeration":
                        self.directory_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "PostMatch":
                        self.postmatch_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "ContentsEnumeration":
                        self.contents_classifiers.append(dict_rule)
                    else:
                        log.warning(
                            f"{dict_rule['RuleName']} is invalid, please check your syntax!")

# TODO

def is_interest_file(file:RemoteFile, rules: Rules, smb_client: SMBClient, share):
    backup_ext_list = [".bak", ".mdf", ".sqldump", ".sdf"]
    cred_list = ["creds", "password", "passw", "credentials", "login", "secret", "account", "pass",
                 ".kdb",".psafe3",".kwallet",".keychain",".agilekeychain",".cred"]

    file_text = termcolor.colored(f"[File]", "green")
    ssn_regex = str("^\d{{3}}-\d{{2}}-\d{{4}}$")

    # Non-file shares
    if str(share).lower().find("ipc") or str(share).lower().find("print"):
        pass
    else:
        file_data = ""
        file.get(smb_client)

        # MVP Build only, check for SSN in files
        with open(str(file.tmp_filename)) as f:
            file_data = f.read(10000)
            if re.search(ssn_regex, file_text):
                file_triage = termcolor.colored(f"{{Red}}\\\\{file.target}\\{share}\\{file.name} <SsnRegexFound>", "light_yellow", "on_white")
                print(file_text, file_triage)

        # MVP Build only, check for backup files
        for ext in backup_ext_list:
            if re.search(str(ext), str(file.name).lower()):
                file_triage = termcolor.colored(f"{{Yellow}}\\\\{file.target}\\{share}\\{file.name} <KeepBackupFiles>", "light_yellow", "on_white")
                try:
                    file.get(smb_client)
                    print(file_text, file_triage)
                except FileRetrievalError as e:
                    smb_client.handle_download_error(share, file.name, e)

        # MVP Build only, check for files with possible passwords contained inside         
        for cred in cred_list:
            if re.search(str(cred), str(file.name).lower()):
                file_triage = termcolor.colored(f"{{Black}}\\\\{file.target}\\{share}\\{file.name} <KeepFilesWithInterestName>", "black", "on_white")
                file.get(smb_client)
                print(file_text, file_triage)
    



def is_interest_share(share, rules: Rules):
    
    # Tedium City to find match in wordlist. Did not prepare rules beforehand except by putting each MatchLocation in its own list
    # so I have to do more work here before I can find the match

    for rule in rules.share_classifiers:
        regex_rules = []
        share_text = termcolor.colored("[Share]", 'light_yellow')
        default_triage = termcolor.colored(f"{share}", 'green')
        if rule['WordListType'] == "Regex":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>",str(color).lower(), 'on_white'))
                    else: 
                        log.debug(f"{rule['MatchAction']} {share} matched rule {rule['RuleName']}:{rule['Description']}")

        elif rule['WordListType'] == "EndsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern + "$"), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>",str(color).lower(), 'on_white'))
                    else: 
                        log.debug(f"{rule['MatchAction']} {share} matched rule {rule['RuleName']}:{rule['Description']}")

        elif rule['WordListType'] == "StartsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern), str(share)) is not None:
                    color = rule['Triage']
                    print(share_text, termcolor.colored(f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>",str(color).lower(), 'on_white'))

        elif rule['WordListType'] == "Contains":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>",str(color).lower(), 'on_white'))
                    else: 
                        log.debug(f"{rule['MatchAction']} {share} matched rule {rule['RuleName']}:{rule['Description']}")

        elif rule['WordListType'] == "Exact":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern + "$"), str(share)) is not None:
                    if rule['MatchAction'] == "Snaffle":
                        color = rule['Triage']
                        print(share_text, termcolor.colored(f"{{{rule['Triage']}}} {share} <{rule['RuleName']}>:<{rule['Description']}>",str(color).lower(), 'on_white'))
                    else: 
                        log.debug(f"{rule['MatchAction']} {share} matched rule {rule['RuleName']}:{rule['Description']}")

        else:
            log.warning(f"{rule['RuleName']} has an invalid WordListType - valid values are Regex, EndsWith, StartsWith, Contains, or Exact")
            raise Exception("Invalid WordListType")
