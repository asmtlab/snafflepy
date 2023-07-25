import re
import toml
import os
import logging
# import pprint
import termcolor

from impacket.smbconnection import SessionError, SMBConnection
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

def is_interest_file(file:RemoteFile, rules, smb_client) -> bool:
    file.get(smb_client)
    '''
    interest_names = []
    if file.get_shortname() in interest_names:
        return True
    else:
        return False
    '''
def is_interest_share(share, rules: Rules):
    
    # Tedium City to find match in wordlist. Did not prepare rules beforehand except by putting each MatchLocation in its own list
    # so I have to do more work here before I can find the match

    for rule in rules.share_classifiers:
        regex_rules = []
        share_text = termcolor.colored("[Share]", 'yellow')
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
