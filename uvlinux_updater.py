#! /usr/bin/env python

'''
script name: uvlinux_updater.py
date:        22.12.2017
author:      Kai Scharwies (Seven Principles AG) [kai.scharwies@7p-group.com]
dependency:  python 2.7.x or higher (addon package python-configparser required)
             python 3.2.x or higher
description: This script downloads and extracts the virus definition data used
             by the McAfee uvscan command line virus scanner available on a
             public server.
             Upon success the script returns '0', otherwise '1'.
             Settings like http(s)-proxy, download URL and path to extract to
             are set to working defaults, but can be modified using an INI-style
             configuration file (sample and default values as follows).
             The configuration file can either be named 'uvlinux_updater.cfg',
             located in the same directory as the script, or its path can be
             supplied as a command line argument, e.g.:
                 ./uvlinux_updater.py /etc/uvlinux_updater.cfg
sample cfg:
             [Config]
             use_proxy = true
             proxy_protocol = https
             proxy_url = http://10.0.1.12:3128
             base_url = https://update.nai.com/products/commonupdater
             ini_file = avvdat.ini
             extract_path = /usr/local/uvscan/
'''

from configparser import ParsingError, ConfigParser
from tempfile import gettempdir
from hashlib import md5
from ssl import SSLContext, PROTOCOL_SSLv23, OP_NO_TLSv1, OP_NO_SSLv3, OP_NO_SSLv2, OP_NO_COMPRESSION
from zipfile import ZipFile
from os import remove, path
from sys import version_info, exit, argv
from contextlib import closing

# Python 3
if (version_info > (3, 0)):
    import urllib.request as ur
# Python 2
else:
    import urllib2 as ur

def unzip(source_filename, dest_dir):
    with ZipFile(source_filename) as zf:
        zf.extractall(dest_dir)

def md5match(fname, hashcheck):
    hash_md5 = md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return (hash_md5.hexdigest() == hashcheck)

def getcurrent_filename_and_hash(proxy_handl, ssl_cont, url):
    # dummy return values in case getting actual values fails
    returntuple = '', 0, ''

    https_handler = ur.HTTPSHandler(context=ssl_cont)

    # prepare wrapper for our https connection
    opener = ur.build_opener(proxy_handl, https_handler)
    ur.install_opener(opener)

    # open https connection
    try:
        resp = opener.open(url)
    except Exception as e:
        print(e)
        pass    
    else:
        config = ConfigParser(interpolation=None)

        # read ini from https connection
        try:
            config.read_string(''.join(resp.read().decode('utf-8')))
        except ParsingError:
            pass

        # return values for options FileName and MD5 from section AVV-ZIP (options are not casesensitive)
        if config.has_option('AVV-ZIP', 'filename') and config.has_option('AVV-ZIP', 'md5') and config.has_option('AVV-ZIP', 'filepath'):
            returntuple = config.get('AVV-ZIP', 'filename'), config.get('AVV-ZIP', 'md5'), config.get('AVV-ZIP', 'filepath')
            
    return returntuple

def download_archive(base_url, filename, proxy_handl, ssl_cont):
    tempdir = gettempdir()
    url = base_url + filename
    print('Downloading ' + url + ' into ' + tempdir)
    target_file_name = path.join(tempdir, filename)

    https_handler = ur.HTTPSHandler(context=ssl_cont)

    # prepare wrapper for our https connection
    opener = ur.build_opener(proxy_handl, https_handler)
    ur.install_opener(opener)

    # download file
    with open(target_file_name, 'wb') as out_file:
        with closing(ur.urlopen(url)) as fp:
            block_size = 1024 * 8
            while True:
                block = fp.read(block_size)
                if not block:
                    break
                out_file.write(block)
        
    return target_file_name

def main():
    # initialize variables used through the main function
    exitcode = 1
    use_proxy = True
    proxy_protocol = ''
    proxy_url = ''
    base_url = ''
    ini_file = ''
    extract_path = ''

    # read configuration file name if supplied as command line argument
    if len(argv) > 1:
        cfg_file_name = str(argv[1])
    else:
        cfg_file_name = 'uvlinux_updater.cfg'

    # try to parse configuration, otherwise use default settings
    try:
        config = ConfigParser(interpolation=None)
        config.read(cfg_file_name)
        use_proxy = config.getboolean('Config', 'use_proxy')
        if use_proxy:
            proxy_protocol = config.get('Config', 'proxy_protocol')
            proxy_url = config.get('Config', 'proxy_url')
        base_url = config.get('Config', 'base_url')
        ini_file = config.get('Config', 'ini_file')
        extract_path = config.get('Config', 'extract_path')
        print('Successfully read settings from configfile ' + cfg_file_name)
    except Exception as e:
        print(e)
        print('Failed to read settings from configfile ' + cfg_file_name + '. Using default settings.')
        use_proxy = True
        proxy_protocol = 'https'
        proxy_url = 'http://10.0.14.121:3128'
        base_url = 'https://update.nai.com/products/commonupdater'
        ini_file = 'avvdat.ini'
        extract_path = '/usr/local/uvscan/'
        pass
    
    # set up handler for our http(s) proxy
    proxy_handler = ur.ProxyHandler()
    if use_proxy:
        proxy_handler = ur.ProxyHandler({proxy_protocol: proxy_url})

    # set up handler to allow only secure protocols, but do not verify hostname against certificate, as it does not match ('update.nai.com' vs. 'a248.e.akamai.net')
    ssl_context = SSLContext(PROTOCOL_SSLv23)
    ssl_context.options |= OP_NO_TLSv1
    ssl_context.options |= OP_NO_SSLv3
    ssl_context.options |= OP_NO_SSLv2
    ssl_context.options |= OP_NO_COMPRESSION
    ssl_context.check_hostname = False
    
    # pull filename of most current archive (e.g. avvdat-8737.dat) & md5 hash from ini file on McAfee Server
    filename, hash_md5, filepath = getcurrent_filename_and_hash(proxy_handler, ssl_context, base_url + '/' + ini_file)

    # clean up returned values/types if needed (Python 2 Backport of Python 3 configparser module quirk)
    if type(filename) is list:
        filename = str(filename[0])
    if type(hash_md5) is list:
        hash_md5 = str(hash_md5[0])

    # check whether getcurrent_filename_and_hash() was successful
    if filename == '':
        print("Error, could not get current filename")
    else:
        # download current archive (e.g. avvdat-8737.dat) from McAfee Server
        tmp_file = download_archive(base_url + filepath, filename, proxy_handler, ssl_context)

        # prepare path archive will be extracted to
        #dest_dir = path.join(extract_path)
        
        # only extract if downloaded and actual md5 matches
        if md5match(tmp_file, hash_md5):
            
            print('MD5 hash matches, extracting ' + str(tmp_file) + ' to ' + extract_path)
            try:
                unzip(tmp_file, extract_path)
            except Exception as e:
                print(e)
                pass
            else:
                print('Extracted successfully into ' + extract_path)
                exitcode = 0
        else:
            print('MD5 hash does not match!')

        # remove downloaded archive in either case
        print('Removing downloaded archive ' + str(tmp_file))
        try:
            remove(tmp_file)
        except Exception as e:
            print(e)
   
    return(exitcode)

if __name__ == "__main__":
    exit(main())
