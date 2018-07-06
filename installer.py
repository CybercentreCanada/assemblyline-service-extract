#!/usr/bin/env python
import os

def install(alsi):
    alsi.sudo_apt_install([
        'p7zip-full', 
        'p7zip-rar',
        'libarchive-dev',
        'unace-nonfree'
    ])

    alsi.pip_install_all([
        'python-libarchive==3.1.2-1',
        'tnefparse',
        'olefile'
    ])

    # MSOffice Tool for better MSOffice decoding support
    # https://github.com/herumi/msoffice (master copied Jul 2018)

    local_support = os.path.join(alsi.alroot, 'support/extract/')
    local_work = os.path.join(local_support, 'work')
    local_msoffice = os.path.join(local_support, 'msoffice.tar.gz')
    local_cybozulib = os.path.join(local_support, 'cybozulib.tar.gz')

    os.makedirs(local_work)
    alsi.fetch_package('extract/msoffice.tar.gz', local_msoffice)
    alsi.fetch_package('extract/cybozulib.tar.gz', local_cybozulib)

    wd = os.getcwd()
    os.chdir(local_support)
    alsi.runcmd("tar -zxf msoffice.tar.gz")
    alsi.runcmd("tar -zxf cybozulib.tar.gz")
    os.chdir(os.path.join(local_support, "msoffice"))
    alsi.runcmd("make -j RELEASE=1")
    os.chdir(wd)

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
