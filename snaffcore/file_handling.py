from .utilities import *
from .errors import *
# from .classifier import is_interest_file
from pathlib import Path
import os
import termcolor


# RT: Stolen from manspider - https://github.com/blacklanternsecurity/MANSPIDER


class RemoteFile():
    '''
    Represents a file on an SMB share
    Passed from a spiderling up to its parent spider    
    '''

    def __init__(self, name, share, target, size=0, smb_client=None):

        self.share = share
        self.target = target
        self.name = name
        self.size = size
        self.smb_client = smb_client

        does_exist = os.path.exists("remotefiles")
        if not does_exist:
            log.info("remotefiles directory not present, creating dir")
            os.makedirs("remotefiles")

        # file_suffix = Path(name).suffix.lower()
        self.tmp_filename = Path('./remotefiles') / \
            (self.name)

        # self.tmp_filename = Path('/tmp/.snafflepy') / \
        #     (random_string(15) + file_suffix)

    def get(self, smb_client=None):
        '''
        Downloads file to self.tmp_filename

        NOTE: SMBConnection() can't be passed through a multiprocessing queue
              This means that smb_client must be set after the file arrives at Spider()
        '''

        if smb_client is None and self.smb_client is None:
            raise FileRetrievalError('Please specify smb_client')

        # memfile = io.BytesIO()
        with open(str(self.tmp_filename), 'wb') as f:

            try:
                smb_client.conn.getFile(self.share, self.name, f.write)
            except Exception as e:
                handle_impacket_error(e, smb_client, self.share, self.name)
                raise FileRetrievalError(
                    f'Error retrieving file "{str(self)}": {str(e)[:150]}')

        # reset cursor back to zero so .read() will return the whole file
        # memfile.seek(0)

    def __str__(self):

        return f'\\\\{self.target}\\{self.share}\\{self.name}'

    def handle_download_error(self, dir_path, err, is_from_go_loud: bool, add_err: bool):
        # subfiles = []

        if str(err).find("DIRECTORY"):
            dir_text = termcolor.colored("[Directory]", 'light_blue')

            if is_from_go_loud:
                log.info(
                    f"{dir_text} \\\\{self.target}\\{self.share}\\{dir_path}")
            try:
                subfiles = self.smb_client.ls(self.share, str(dir_path))
                add_err = False
            

                for subfile in subfiles:
                    sub_size = subfile.get_filesize()
                    sub_name = str(dir_path + "\\" + subfile.get_longname())

                    try:
                        subfile = RemoteFile(
                            sub_name, self.share, self.target, sub_size)
                        if is_from_go_loud:
                            subfile.get(self.smb_client)
                        # else: 
                            # is_interest_file(self, self.smb_client, self.share)
                        add_err = False

                    except FileRetrievalError as e:
                        # handle_impacket_error(e, subfile.smb_client, subfile.share, sub_name, True)
                        err = e
                        add_err = True

                    finally:
                        if add_err:
                            # print(error)
                            self.handle_download_error(
                                sub_name, err, is_from_go_loud, True)
                        else:
                            file_text = termcolor.colored("[File]", 'green')
                            if is_from_go_loud:
                                log.info(
                                    f"{file_text} \\\\{self.target}\\{self.share}\\{sub_name}")
            except FileListError as e:
                if is_from_go_loud:
                    log.error(
                        f"Access denied, cannot read at {self.target}\\{self.share}\\{dir_path}")
