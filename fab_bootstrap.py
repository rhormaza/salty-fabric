#!/usr/bin/env python26

# Python libs
import sys

from socket import gethostbyname as _gethostbyname, \
                  gethostname as _gethostname

# Fabric libs
from fabric.api import *
from fabric.contrib import files

# TODO(raul): find a better way so we don't need to hardcode
HOST_TO_ADD = {
    'salt': '10.188.49.191',
    'salt2': '10.188.49.190',
}

# Packages needed!
SALT_PKGS = (
    'libzmq3-3.2.2-13.1',
    'libffi-3.0.5-1.el5',
    'libyaml-0.1.2-6.el5',
    'gmp-4.1.4-10.el5',
    'sshpass-1.05-1.el5',
    'yum-utils-1.1.16-21.el5',
    'python26-libs-2.6.8-2.el5',
    'python26-2.6.8-2.el5',
    'python26-markupsafe-0.11-3.el5',
    'python26-crypto-2.3-5.el5',
    'python26-msgpack-0.1.12-2.el5',
    'python26-zmq-13.1.0-1',
    'python26-m2crypto-0.21.1-5.el5',
    'python26-PyYAML-3.08-4.el5',
    'python26-babel-0.9.5-2.el5',
    'python26-jinja2-2.5.5-4.el5',
    'salt-2014.1.0-1.el5',
    'salt-minion-2014.1.0-1.el5',
)

class _WrongFormatError(Exception):
    pass

class _NeedSudoError(Exception):
    pass

class _CmdFailedError(Exception):
    pass

# TODO(raul) move this away from this file 
def _get_repo_ip():
    '''
    Get the IP of the this host.
    '''
    return _gethostbyname(_gethostname())

def _yum(subcmd, pkgs=None, force=True, nogpgcheck=True, use_sudo=True):
    '''
    This run a `yum` command such as yum -y `subcmd` pkgs
    '''

    if not use_sudo:
        raise _NeedSudoError("You need to run this as sudo!")

    data = {}
    
    if force:
        data['force'] = '-y'
    if nogpgcheck:
        data['nogpgcheck'] = '--nogpgcheck'
    if pkgs:
        if type(pkgs) == type(str()):
            data['pkgs'] = pkgs
        elif type(pkgs) == type(list()) or type(pkgs) == type(tuple()):
            data['pkgs'] = ' '.join(pkgs)
        else:
            raise _WrongFormatError('pkgs variable has a unsupported format.')
    else:
        if subcmd in ['upgrade', 'update']:
          pkgs = ''
        else:
            raise _WrongFormatError('pkgs variable has a unsupported format.')

    data['subcmd'] = subcmd
    
    return sudo('yum {force} {nogpgcheck} {subcmd} {pkgs}'.format(**data))
    
def _is_minion_installed():
    out = sudo('rpm -qa| grep salt-minion')
    if out.succeeded:
        return True
    else:
        return False

def _is_sudo():
    '''
    Checks if we have sudo permissions in the target machine

    Check is performed by sudo -v
    '''
    
    with settings(warn_only='true'):
        out = run('sudo -v')
        if out.succeeded:
            return True
        else:
            return False

def _install_repo(reponame, repotype='yum', use_sudo=True, update_cache=True, force=True):
    '''
    Install a repo by copying the file from local to remote.

    When using update_cache=True, you *must* use use_sudo=True. This is
    also the default behaviour.
    
    TODO(raul): add other systems if needed (debian, ubuntu, etc)
                force option?
    '''
    repopath = {
        'yum' : '/etc/yum.repos.d',
        # TODO(raul) add more here!
    }.get(repotype)

    out = put(reponame, '{0}/{1}'.format(repopath, reponame), use_sudo=use_sudo)

    if out.succeeded and update_cache:
        out = sudo('yum -y --nogpgcheck makecache')
        return out.succeeded if out.succeeded else False
    elif out.succeeded:
        return True
    else:
        return False

def _add_minion_id(minion_id, minion_id_file='/etc/salt/minion_id', use_sudo=True):
    '''
    Helper function to add minion_id to /etc/salt/minion_id
    '''
    if not use_sudo:
        raise _NeedSudoError("You need to run this as sudo!")
    files.append(minion_id_file, minion_id, use_sudo=use_sudo)

def _put_minion_debug_mode(minion_cnf_file='/etc/salt/minion', log_level='log_level: trace', use_sudo=True):
    '''
    Helper function to put minion in debug mode 
    '''
    if not use_sudo:
        raise _NeedSudoError("You need to run this as sudo!")
    files.append(minion_cnf_file, log_level, use_sudo=use_sudo)
    
def _remove_salt_dirs(use_sudo=True):
    '''
    Helper function to delete /etc/salt directory
    '''
    if not use_sudo:
        raise _NeedSudoError("You need to run this as sudo!")
    
    for d in ['/etc/salt', '/var/run/salt*', '/var/cache/salt']: 
        out = sudo('rm -rf {0}'.format(d))
        if out.failed:
            _CmdFailedError()

def _check_repo_dict(repos):
    '''
    This assumes that dictionary is like below:
    
    d = {
      'r1': 'repofile.repo',
      'r2': 'anotherfile.repo',
      ...
      ...
      'rN': 'N_file_with_repo_extension.repo'
    }

    For now, the only check is to make sure all files end with *.repo
    and then return this as a list.
    
    '''

    for k,v in repos.items():
        if v[-5:] != '.repo':
            raise  _CmdFailedError("{0} repo seems to be invalid".format(v))
    
    return repos.values()

def add_etc_host_entry(host, ip, hosts_file='/etc/hosts', use_sudo=True):
    '''
    Helper function to add an entry in /etc/hosts
    '''
    files.append(hosts_file, '{0} {1}'.format(ip, host), use_sudo=use_sudo)

def remove_etc_host_entry(host, ip, hosts_file='/etc/hosts', use_sudo=True):
    '''
    Helper function to remove an entry in /etc/hosts
    '''
    files.sed('/etc/hosts', '^{0}.*{1}'.format(ip, host), '', use_sudo=True)

def remove_minion_pki_from_master():
    '''
    Helper function to remove the pki from minion in the master

    This assumes the master is running in the same machine than fabric!

    Process:
    
    1.- Get current minion_id from remote end
    2.- Remove key from *local* master....remember master must be running
        in this machine 
    '''
    minion_id = sudo("cat /etc/salt/minion_id")
    local('rm -rf /etc/salt/pki/master/minions/{0}*'.format(str(minion_id)))

@task
def install_minion(minion_id, type="rhel5_x86_64", **repos):
    '''
    Install and configure target minion
    
    1.- Setup /etc/hosts
    2.- Setup and update yum repo
    3.- Install salt minion
    4.- Assigns ID to minion (minimal setup)
    5.- Restart minion
    6.- Done

    # TODO(raul): This just installs in a redhat-family server. 
    #             No Ubuntu, Suse, etc support yet.
    '''
    if len(repos) == 0:
        raise _CmdFailedError("You need to add the repos to be installed in the target host.")
    else:
        repos = _check_repo_dict(repos)

    
    with settings(warn_only='true'):
        # Let's check the type of server
        if type[:4] == 'rhel':  
            add_sudo_and_sshkey()
            if _is_minion_installed():
                print "minion is already installed" 
                sys.exit(0)

            run_yum = False
          
            # Note(raul): If one entry fails to be added then program will exit,
            # so no need to take care in much detail.
            for host, ip in HOST_TO_ADD.items():
                add_etc_host_entry(host, ip, use_sudo=True)

            # Use list() just in case more repos are needed in the future
            for repo in repos: 
                if _install_repo(repo):
                    run_yum = True
                else:
                    print "An error happened when installing the repo file(s): {0}".format(repo)
                    sys.exit(-1)


            if run_yum:
                out = _yum('install', SALT_PKGS)
                if out.succeeded:
                    # Some post-install config
                    _add_minion_id(minion_id)
                    _put_minion_debug_mode()
                    restart_minion()
@task
def uninstall_minion(type="rhel5_x86_64"):
    '''
    Stops and uninstall salt minion on target host
    '''
    with settings(warn_only='true'):
        # Let's check the type of server
        if type[:4] == 'rhel':  
            run_yum = True

            if run_yum:
                stop_minion()
                out = _yum('erase', SALT_PKGS)

                for host, ip in HOST_TO_ADD.items():
                    remove_etc_host_entry(host, ip, use_sudo=True)

                remove_minion_pki_from_master()

                # TODO(raul): decide to delete or not this
                # Remove salt dir
                #_remove_salt_dirs()

@task
def stop_minion():
    '''
    Stop salt minion on target host
    '''
    sudo("service salt-minion stop")

@task
def restart_minion():
    '''
    Restart salt minion on target host
    '''
    sudo("service salt-minion restart")

@task
def check_minion_status():
    sudo("service salt-minion status")

@task
def tail_minion_log(lines=30):
    sudo("tail -n{0} /var/log/salt/minion".format(lines))

@task
@task
def set_minion_onboot():
    '''
    Set minion to start when machine boots
    '''
    sudo("chkconfig salt-minion on")

@task
def set_minion_iptables_rules():
    '''
    Add minimal iptables rules to allow salt to work.

    # TODO(raul): what if iptables is not installed..
    # should we consider some better error handling?
    '''
    cmd = '''if [[ $(grep -E "A.*INPUT.*dports.*4505.*4506.*ACCEPT" /etc/sysconfig/iptables) ]]; then
            echo "Iptables rules already there."
        else
            iptables -A INPUT -p tcp -m multiport --dports 4505,4506 -j ACCEPT && service iptables save
        fi 
    '''
    sudo(cmd)

@task
def add_sudo():
    '''
    Add ``sudo`` permissions to target host

    # TODO(raul): Better error handling
    '''

    # Note(raul): ``sudo`` string looks ugly but it has to be that way
    sudo = '''
admin ALL=(ALL) NOPASSWD: ALL
Defaults:admin !requiretty
'''
    sudoer_file = '/etc/sudoers.d/salt_bootstrap'
    tmp_file = '/tmp/.sudoer_file'

    run('cat > {1} << EOF{0}EOF'.format(sudo, tmp_file))
    # FIXME(raul): root account is "disabled" by setting password to expire...hence use sudo :)
    run('sudo su -c "chmod 0440 {0} && chown root.root {0} && mv {0} {1}"'.format(tmp_file, sudoer_file))

@task
def add_sshkey():
    '''
    Basic method to set ssh keys using fabric
    '''
    keyfile = "/tmp/%s.pub" % env.user
    ssh_auth_keys = "~/.ssh/authorized_keys"
    run("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    out = put('~/.ssh/id_rsa.pub', keyfile)
    if out.succeeded:
        # TODO(raul): Replace this with contrib.file API?
        run("if [[ $(grep \"$(cat {0})\" {2}) ]]; then echo {1}; else cat {0} >> {2}; fi".format(
            keyfile, 
            "SSH key already there",
            ssh_auth_keys))
        run("chmod 600 ~/.ssh/authorized_keys")
        run("rm %s" % keyfile)

@task
def add_sudo_and_sshkey():
    '''
    Helper function to check sudo rights and if not found
    add them. It also adds the ssh keys, no check performed. 

    # TODO(raul): check for ssh keys?
    '''
    # FIXME(raul): this check doesnt work!
    #if not _is_sudo():
    add_sudo()
    add_sshkey()

if __name__ == '__main__':
    # FIXME(raul): improve usage and info here
    print "Usage:"
    print "fab -H 10.188.49.28 -f fab_bootstrap.py -u admin check_minion_status"
