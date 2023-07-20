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


def is_interest(file, rules):
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
