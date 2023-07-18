import re
import toml
from impacket.smbconnection import SessionError, SMBConnection
import os

# TODO 
class Rules:
    def __init__(self) -> None:
        self.classifier_rules = []
        self.share_classifiers = []
        self.directory_classifiers = []
        self.file_classifiers = []
        self.contents_classifiers = []
        self.postmatch_classifiers = []


    def prepare_classifiers():
        snafflepy_path = "./snaffcore/DefaultRules/"

        toml_dict = []
        for root, dirs, files in os.walk(snafflepy_path, topdown=False):
            for name in files:
                print(os.path.join(root,name))
                with open(os.path.join(root, name), 'r') as tfile:
                    toml_dict.append(toml.load(tfile))

        return toml_dict



def is_interest(file):
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