import re
import toml
import os
import logging
import pprint

from impacket.smbconnection import SessionError, SMBConnection


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

        #pprint.pprint(self.share_classifiers)
        # pprint.pprint(self.directory_classifiers)
        # pprint.pprint(self.file_classifiers)
        # pprint.pprint(self.contents_classifiers)
        # pprint.pprint(self.postmatch_classifiers)

# TODO


def is_interest_file(file, rules) -> bool:
    # massive_wordlist = prepare_classifiers()
    # print(massive_wordlist)
    # for root, dirs, files in os.walk(snafflepy_path, topdown=False):
    #     for name in files:
    #         with open(os.path.join(root, name), 'rb') as tfile:
    #             print(toml.loads(tfile))

    interest_names = ["Creds.txt"]
    if file.get_shortname() in interest_names:
        return True
    else:
        return False

def is_interest_share(share, rules: Rules):
    regex_rules = []
    # Tedium City to find match in wordlist. Did not prepare rules beforehand except by putting each MatchLocation in its own list
    # so I have to do more work here before I can find the match

    for rule in rules.share_classifiers:
        if rule['WordListType'] == "Regex":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(share)) is not None:
                    log.info(f"{share} matched {rule['RuleName']}:{rule['Description']}")

        elif rule['WordListType'] == "EndsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern + "$"), str(share)) is not None:
                    if rule['MatchAction'] == 'Snaffle':
                        log.info(f"{share} matched rule {rule['RuleName']}:{rule['Description']}")
                    else: 
                        log.debug(f"{rule['MatchAction']} {share} matched rule {rule['RuleName']}:{rule['Description']}")

        elif rule['WordListType'] == "StartsWith":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern), str(share)) is not None:
                    log.warning(f"{share} matched rule {rule['RuleName']}: {rule['Description']}")

        elif rule['WordListType'] == "Contains":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str(pattern), str(share)) is not None:
                    log.warning(f"{share} matched rule {rule['RuleName']}:{rule['Description']}")

        elif rule['WordListType'] == "Exact":
            regex_rules = rule['WordList']
            for pattern in regex_rules:
                if re.search(str("^" + pattern + "$"), str(share)) is not None:
                    print(f"{share} matched {rule['RuleName']}:{rule['Description']}")

        else:
            log.warning(f"{rule['RuleName']} has an invalid WordListType - valid values are Regex, EndsWith, StartsWith, Contains, or Exact")
