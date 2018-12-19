#!/usr/bin/env python3

import re          # 6.2
import pathlib     # 11.1
import stat        # 11.4
import tempfile    # 11.6
import argparse    # 16.4
import getpass     # 16.9
import subprocess  # 17.5
import socket      # 18.1
import json        # 19.2
import base64      # 19.6
from typing import Tuple, Optional, List, Set, Union, NewType  # 26.1
import sys         # 29.1
import jsonschema
import yaml

_verbosity = 0


def _print_info(*args, **kwargs) -> None:
    if _verbosity < 1:
        return
    print(*args, **kwargs)


def _print_debug(*args, **kwargs) -> None:
    if _verbosity < 2:
        return
    print(*args, **kwargs)


def _get_current_username() -> str:
    return getpass.getuser()


def _run_process(args: List[str], **kwargs) -> subprocess.CompletedProcess:
    _print_debug(f"Executing the following command: `{args}'.")
    if 'encoding' not in kwargs or kwargs['encoding'] is None:
        kwargs['encoding'] = 'UTF-8'
    if 'stdout' not in kwargs or kwargs['stdout'] is None:
        kwargs['stdout'] = subprocess.PIPE
    if 'stderr' not in kwargs or kwargs['stderr'] is None:
        kwargs['stderr'] = subprocess.PIPE
    process = subprocess.run(args, **kwargs)
    _print_debug(f'''stdout: {process.stdout}
stderr: {process.stderr}
returncode: {process.returncode}''')
    return process


class Keytype(object):
    def __init__(self, keytype: str):
        if keytype not in ('dsa', 'rsa', 'ecdsa', 'ed25519'):
            raise RuntimeError(f"An invalid keytype `{keytype}'.")
        self._keytype = keytype

    def __repr__(self) -> str:
        return self._keytype

    def __eq__(self, other: 'Keytype') -> bool:
        return self._keytype == other._keytype

    def __hash__(self) -> int:
        return hash(self._keytype)


class FineGrainedKeytype(object):
    def __init__(self, keytype: str):
        if keytype not in ('ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                           'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                           'ssh-ed25519'):
            raise RuntimeError(f"An invalid keytype: `{keytype}'.")
        self._keytype = keytype

    def __repr__(self) -> str:
        return self._keytype

    def __eq__(self, other: 'FineGrainedKeytype') -> bool:
        return self._keytype == other._keytype

    def __hash__(self) -> int:
        return hash(self._keytype)

    def get_readable_type(self) -> str:
        if self._keytype == 'ssh-dss':
            return 'DSA'
        if self._keytype == 'ssh-rsa':
            return 'RSA'
        if self._keytype in ('ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                             'ecdsa-sha2-nistp521'):
            return 'ECDSA'
        if self._keytype == 'ssh-ed25519':
            return 'Ed25519'
        raise RuntimeError(f"An invalid keytype: `{self._keytype}'.")


class Options(object):
    def __init__(self):
        argparser = argparse.ArgumentParser(
            description='Authorize public-key-based SSH login among users \
specified by an Ansible inventory file and a config file.')
        argparser.add_argument('config_file', metavar='CONFIG_FILE',
                               help='The path to a config file.')
        argparser.add_argument(
            '-i', '--inventory', metavar='INVENTORY_FILE',
            help='Specify the path to an Ansible inventory file.')
        argparser.add_argument('--ask-vault-pass', action='store_true',
                               help='Ask for Ansible Vault password.')
        argparser.add_argument(
            '--vault-password-file', metavar='VAULT_PASSWORD_FILE',
            help='The path to an Ansible Vault password file.')
        argparser.add_argument('--use-rsh', action='store_true',
                               help="Use `rsh' to prepare public-key-based \
SSH authorization to remote machines.")
        argparser.add_argument(
            '--identity-algorithms', metavar='ALGORITHMS',
            default='ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa',
            help='Specify the algorithms of user identities in order of \
preference (default: %(default)s).')
        argparser.add_argument(
            '--key-comment', metavar='COMMENT',
            default='added by ssh-prepare.py',
            help='Add COMMENT to public keys when they are generated and \
added to authorized keys files (default: "%(default)s").')
        argparser.add_argument('--dry-run', '-n', action='store_true',
                               help='Show all authorizee-target pairs \
specified by the config file and exit.')
        argparser.add_argument('--verbose', '-v', action='count',
                               help='Increase the verbosity.')
        args = argparser.parse_args()

        self._inventory_file_path = None
        if args.inventory is not None:
            self._inventory_file_path = pathlib.Path(args.inventory)
            if not self._inventory_file_path.exists():
                print(f"The file `{self._inventory_file_path}' does not \
exist.", file=sys.stderr)
                sys.exit(1)
            if not self._inventory_file_path.is_file():
                print(f"`{self._inventory_file_path}' is not a file.",
                      file=sys.stderr)
                sys.exit(1)

        self._ask_vault_pass = args.ask_vault_pass

        self._vault_password_file_path = None
        if args.vault_password_file is not None:
            if self._ask_vault_pass:
                print(f"`--ask-vault-pass' and `--vault-password-file' are \
mutually exclusive.", file=sys.stderr)
                sys.exit(1)
            self._vault_password_file_path \
                = pathlib.Path(args.vault_password_file)
            if not self._vault_password_file_path.exists():
                print(f"The file `{self._vault_password_file_path}' does not \
exist.", file=sys.stderr)
                sys.exit(1)
            if not self._vault_password_file_path.is_file():
                print(f"`{self._vault_password_file_path}' is not a file.",
                      file=sys.stderr)
                sys.exit(1)

        self._config_file_path = pathlib.Path(args.config_file)
        if not self._config_file_path.exists():
            print(f"The file `{self._config_file_path}' does not exist.",
                  file=sys.stderr)
            sys.exit(1)
        if not self._config_file_path.is_file():
            print(f"`{self._config_file_path}' is not a file.",
                  file=sys.stderr)
            sys.exit(1)

        self._use_rsh = args.use_rsh

        self._user_identity_preference = []
        for keytype in args.identity_algorithms.split(','):
            if keytype not in ('ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                               'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                               'ssh-ed25519'):
                print(f"An invalid keytype `{keytype}'.", file=sys.stderr)
                sys.exit(1)
            self._user_identity_preference.append(FineGrainedKeytype(keytype))
        if len(self._user_identity_preference) == 0:
            print("The value of `--identity-algorithms' option is empty.",
                  file=sys.stderr)
            sys.exit(1)

        self._key_comment = args.key_comment

        self._dry_run = args.dry_run

        self._verbosity = 0
        if args.verbose is not None:
            self._verbosity = min(args.verbose, 2)

    @property
    def inventory_file_path(self) -> Optional[pathlib.Path]:
        return self._inventory_file_path

    @property
    def ask_vault_pass(self) -> bool:
        return self._ask_vault_pass

    @property
    def vault_password_file_path(self) -> Optional[pathlib.Path]:
        return self._vault_password_file_path

    @property
    def config_file_path(self) -> pathlib.Path:
        return self._config_file_path

    @property
    def use_rsh(self) -> bool:
        return self._use_rsh

    @property
    def user_identity_preference(self) -> List[FineGrainedKeytype]:
        return self._user_identity_preference

    @property
    def key_comment(self) -> Optional[str]:
        return self._key_comment

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @property
    def verbosity(self) -> int:
        return self._verbosity


class AnsibleInventory(object):
    def __init__(self, inventory_file_path: Optional[pathlib.Path],
                 ask_vault_pass: bool,
                 vault_password_file_path: Optional[pathlib.Path]):
        if ask_vault_pass and vault_password_file_path is not None:
            raise RuntimeError("`ask_vault_pass' and \
`vault_password_file_path' are mutually exclusive.")

        args = ['ansible-inventory']
        if inventory_file_path is not None:
            args.extend(('-i', str(inventory_file_path)))
        if ask_vault_pass:
            args.append('--ask-vault-pass')
        if vault_password_file_path is not None:
            args.extend(('--vault-password-file',
                         str(vault_password_file_path)))
        args.append('--list')

        process = _run_process(args)
        if process.returncode != 0:
            raise RuntimeError(f'''Failed to execute `ansible-inventory'.
args: {process.args}
stdout: {process.stdout}
stderr: {process.stderr}
returncode: {process.returncode}''')

        self._inventory = json.loads(process.stdout)

    def _get_hostvars(self):
        if '_meta' not in self._inventory:
            raise RuntimeError("The key `_meta' is not found in the Ansible \
inventory.")
        meta = self._inventory['_meta']
        if 'hostvars' not in meta:
            raise RuntimeError("The key `hostvars' is not found in the \
Ansible inventory.")
        return meta['hostvars']

    def get_all_hosts(self) -> Set[str]:
        return set(self._get_hostvars().keys())

    def has_host(self, host: str) -> bool:
        return host in self.get_all_hosts()

    def has_group(self, group_name: str) -> bool:
        if group_name == '_meta':
            raise RuntimeError(f"An invalid group name `{group_name}'.")
        return group_name in self._inventory

    def get_group_members(self, group_name: str) -> Set[str]:
        if group_name not in self._inventory:
            raise RuntimeError(f"The group `{group_name}' is not found in \
the Ansible inventory.")

        group = self._inventory[group_name]
        hosts = set()
        if 'hosts' in group:
            hosts.update(group['hosts'])
        if 'children' in group:
            children = group['children']
            for child in children:
                hosts.update(self.get_group_members(child))
        return hosts

    def has_host_variable(self, host: str, variable_name: str) -> bool:
        hostvars = self._get_hostvars()
        if host not in hostvars:
            raise RuntimeError(f"The host `{host}' is not found in the \
Ansible inventory.")
        return variable_name in hostvars[host]

    def dereference_host_variable(self, host: str, variable_name: str):
        hostvars = self._get_hostvars()
        if host not in hostvars:
            raise RuntimeError(f"The host `{host}' is not found in the \
Ansible inventory.")
        hostvars = hostvars[host]
        if variable_name not in hostvars:
            raise RuntimeError(f"The host variable `{variable_name}' of the \
host `{host}' is not found in the Ansible inventory.")
        return hostvars[variable_name]


class Base64EncodedKey(object):
    def __init__(self, key: str):
        try:
            base64.b64decode(key, validate=True)
        except binascii.Error:
            raise RuntimeError(f"An invalid base64-encoded string: `{key}'.")
        self._key = key

    def __repr__(self) -> str:
        return self._key

    def __eq__(self, other: 'Base64EncodedKey') -> bool:
        return self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)


class PublicKey(object):
    def __init__(self, keytype: FineGrainedKeytype, key: Base64EncodedKey,
                 comment: Optional[str] = None):
        self._keytype = keytype
        self._key = key
        self._comment = comment

    @staticmethod
    def from_fields(fields: List[str]) -> 'PublicKey':
        if len(fields) < 2:
            raise RuntimeError(f"Too few elements for a public key: \
`{fields}'.")
        if len(fields) > 3:
            raise RuntimeError(f"Too many elements for a public key: \
`{fields}'.")
        keytype = FineGrainedKeytype(fields[0])
        key = Base64EncodedKey(fields[1])
        comment = None
        if len(fields) == 3:
            comment = fields[2]
        return PublicKey(keytype, key, comment)

    @staticmethod
    def from_string(s: str) -> 'PublicKey':
        return PublicKey.from_fields(s.split(' ', 2))

    def __repr__(self) -> str:
        if self._comment is not None:
            return f'{self._keytype} {self._key} {self._comment}'
        return f'{self._keytype} {self._key}'

    @property
    def _equality_members(self) -> Tuple[FineGrainedKeytype, Base64EncodedKey]:
        return (self._keytype, self._key)

    def __eq__(self, other: 'PublicKey') -> bool:
        return self._equality_members == other._equality_members

    def __hash__(self) -> int:
        return hash(self._equality_members)

    @property
    def keytype(self) -> FineGrainedKeytype:
        return self._keytype

    @property
    def key(self) -> Base64EncodedKey:
        return self._key

    def get_readable_keytype(self) -> str:
        return self._keytype.get_readable_type()

    def get_fingerprint(self) -> str:
        process = _run_process(['ssh-keygen', '-lf', '-'], input=str(self))
        return process.stdout.rstrip('\n')


class ProcessRunner(object):
    def __init__(self, process_runner, *, hostname: Optional[str],
                 login_name: str, sudo_username: Optional[str] = None):
        self._process_runner = process_runner
        self._hostname = hostname
        self._login_name = login_name
        self._sudo_username = sudo_username

    @property
    def hostname(self) -> Optional[str]:
        return self._hostname

    @property
    def login_name(self) -> str:
        return self._login_name

    @property
    def sudo_username(self) -> Optional[str]:
        return self._sudo_username

    def __repr__(self) -> str:
        if self.sudo_username is None:
            s = self.login_name
        else:
            s = self.sudo_username
        if self.hostname is not None:
            s += f'@{self.hostname}'
        if self.sudo_username is not None:
            s += f' (sudo by {self.login_name})'
        return s

    def run(self, args: List[str], **kwargs) -> subprocess.CompletedProcess:
        return self._process_runner(args, **kwargs)

    def print_login_name(self) -> str:
        if self.hostname is None:
            return self.login_name
        return f'{self.login_name}@{self.hostname}'

    def print_path(self, path: pathlib.Path) -> str:
        if not path.is_absolute():
            raise ValueError("`path' must be absolute.")

        if self.hostname is not None:
            return f'{self.hostname}:{path}'
        return path


class TemporaryAskpassFile(object):
    def __init__(self, process_runner: ProcessRunner, password: str):
        self._process_runner = process_runner
        self._password = password
        self._path = None

    def __enter__(self) -> 'TemporaryAskpassFile':
        process = self._process_runner.run(
            ['bash', '-c', 'umask 0077 && mktemp'])
        if process.returncode != 0 or process.stderr != '':
            raise RuntimeError(f"`{self._process_runner}' failed to create a \
temporary file.")
        path = pathlib.Path(process.stdout.rstrip('\n'))

        try:
            process = self._process_runner.run(['chmod', 'u+x', str(path)])
            if process.returncode != 0 or process.stderr != '':
                raise RuntimeError(f"`{self._process_runner}' failed to \
change the mode of the file `{self._process_runner.print_path(path)}'.")

            escaped_password = self._password.replace("'", "'\\''")
            process = self._process_runner.run(
                ['bash', '-c', f"cat >>'{path}'"],
                input=f'''#/usr/bin/env bash

echo -n '{escaped_password}'
''')
            if process.returncode != 0 or process.stderr != '':
                raise RuntimeError("`{self._process_runner}' failed to write \
to the file `{self._process_runner.print_path(path)}'.")

            self._path = path
            return self
        except Exception:
            process = self._process_runner.run(['rm', str(path)])
            if process.returncode != 0 or process.stderr != '':
                print(f"`{self._process_runner}' failed to clean up the \
temporary file `{self._process_runner.print_path(path)}'.", file=sys.stderr)
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        process = self._process_runner.run(['rm', str(self._path)])
        if process.returncode != 0 or process.stderr != '':
            print(f"`{self._process_runner}' failed to clean up the temporary \
file `{self._process_runner.print_path(self._path)}'.", file=sys.stderr)
        self._path = None

    @property
    def path(self) -> pathlib.Path:
        if self._path is None:
            raise ValueError("`path' must be called in an `with' statement.")
        return self._path


class UserOnServer(object):
    def __init__(self, *, hostname: str, port: Optional[int] = None,
                 host_public_key: Optional[PublicKey] = None,
                 login_name: Optional[str] = None,
                 login_password: Optional[str] = None,
                 sudo_username: Optional[str] = None,
                 sudo_password: Optional[str] = None):
        self._hostname = hostname
        self._port = port
        self._host_public_key = host_public_key
        self._login_name = login_name
        self._login_password = login_password
        self._sudo_username = sudo_username
        self._sudo_password = sudo_password

    def __repr__(self) -> str:
        if self.sudo_username is None:
            s = f'{self.login_name}@{self.hostname}'
        else:
            s = f'{self.sudo_username}@{self.hostname}'
        if self.port != 22:
            s += f':{self.port}'
        if self.sudo_username is not None:
            s += f' (sudo by {self.login_name})'
        return s

    @property
    def _equality_members(self) -> Tuple[str, int, str, str]:
        return (self.hostname.lower(), self.port, self.login_name,
                self.sudo_username)

    def __eq__(self, other: 'UserOnServer') -> bool:
        return self._equality_members == other._equality_members

    def __hash__(self) -> int:
        return hash(self._equality_members)

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def port(self) -> int:
        if self._port is None:
            return 22
        return self._port

    @property
    def host_public_key(self) -> Optional[PublicKey]:
        return self._host_public_key

    @property
    def login_name(self) -> str:
        if self._login_name is not None:
            return self._login_name
        return _get_current_username()

    @property
    def login_password(self) -> Optional[str]:
        return self._login_password

    @property
    def sudo_username(self) -> Optional[str]:
        return self._sudo_username

    @property
    def sudo_password(self) -> Optional[str]:
        return self._sudo_password

    def _get_login_user(self) -> 'UserOnServer':
        return UserOnServer(
            hostname=self.hostname, port=self._port,
            host_public_key=self.host_public_key,
            login_name=self._login_name, login_password=self.login_password)

    def _run_process_impl(self, prefix: List[str], args: List[str],
                          login_user_process_runner: Optional[ProcessRunner],
                          **kwargs) -> subprocess.CompletedProcess:
        args = ["'" + arg.replace("'", "'\\''") + "'" for arg in args]

        real_args = prefix

        if self._sudo_username is None:
            assert(login_user_process_runner is None)
            real_args.extend(args)
            return _run_process(real_args, **kwargs)

        if self._sudo_password is None:
            assert(login_user_process_runner is None)
            real_args.extend(('sudo', '-nkHu', self._sudo_username, '--'))
            real_args.extend(args)
            return _run_process(real_args, **kwargs)

        assert(login_user_process_runner is not None)
        with TemporaryAskpassFile(login_user_process_runner,
                                  self._sudo_password) as sudo_askpass_file:
            real_args.extend(
                ('env', f'SUDO_ASKPASS={sudo_askpass_file.path}',
                 'sudo', '-nAkHu', self._sudo_username, '--'))
            real_args.extend(args)
            return _run_process(real_args, **kwargs)

    def run_process_with_rsh(self, args: List[str],
                             **kwargs) -> subprocess.CompletedProcess:
        prefix = ['rsh', '-x']
        if self.login_name != _get_current_username():
            prefix.extend(('-l', self.login_name))
        if ('stdin' not in kwargs or kwargs['stdin'] is None) \
           and ('input' not in kwargs or kwargs['input'] is None):
            prefix.append('-n')
        prefix.append(self.hostname)

        login_user_process_runner = None
        if self._sudo_username is not None and self._sudo_password is not None:
            login_user = self._get_login_user()
            login_user_process_runner = ProcessRunner(
                lambda args, **kwargs:
                login_user.run_process_with_rsh(args, **kwargs),
                hostname=self.hostname, login_name=self.login_name,
                sudo_username=self.sudo_username)

        return self._run_process_impl(prefix, args, login_user_process_runner,
                                      **kwargs)

    def check_rsh(self) -> bool:
        process = self.run_process_with_rsh(['whoami'])
        if process.returncode != 0 or process.stderr != '':
            return False
        if self._sudo_username is None:
            expected_stdout = self.login_name
        else:
            expected_stdout = self._sudo_username
        if process.stdout.rstrip('\n') != expected_stdout:
            raise RuntimeError(f'''An error occurred while checking `rsh' to \
run a process as `{self}'.
args: {process.args}
stdout: {process.stdout}
stderr: {process.stderr}
returncode: {process.returncode}''')
        return True

    def run_process_with_password_based_ssh(
            self, args: List[str], **kwargs) -> subprocess.CompletedProcess:
        infix = ['ssh', '-o', 'StrictHostKeyChecking = yes',
                 '-o', 'PreferredAuthentications = password']
        if self.port != 22:
            infix.extend(('-p', str(self.port)))
        if self.login_name != _get_current_username():
            infix.extend(('-l', self.login_name))
        if ('stdin' not in kwargs or kwargs['stdin'] is None) \
           and ('input' not in kwargs or kwargs['input'] is None):
            infix.append('-n')
        infix.append(self.hostname)

        login_user_process_runner = None
        if self._sudo_username is not None and self._sudo_password is not None:
            login_user = self._get_login_user()
            login_user_process_runner = ProcessRunner(
                lambda args, **kwargs:
                login_user.run_process_with_password_based_ssh(args, **kwargs),
                hostname=self.hostname, login_name=self.login_name,
                sudo_username=self.sudo_username)

        if self._login_password is None:
            return self._run_process_impl_(infix, args,
                                           login_user_process_runner, **kwargs)

        prefix = ['sshpass', '-e']
        prefix.extend(infix)
        return self._run_process_impl(prefix, args,
                                      login_user_process_runner,
                                      env={'SSHPASS': self._login_password},
                                      **kwargs)

    def check_password_based_ssh(self) -> bool:
        process = self.run_process_with_password_based_ssh(['whoami'])
        if process.returncode != 0:
            return False
        if self._sudo_username is None:
            expected_stdout = self.login_name
        else:
            expected_stdout = self._sudo_username
        if process.stdout.rstrip('\n') != expected_stdout:
            raise RuntimeError(f'''An error occurred while checking \
password-based `ssh' to run a process as `{self}'.
args: {process.args}
stdout: {process.stdout}
stderr: {process.stderr}
returncode: {process.returncode}''')
        return True

    def run_process_with_public_key_based_ssh(
            self, args: List[str], **kwargs) -> subprocess.CompletedProcess:
        prefix = ['ssh', '-o', 'BatchMode = yes',
                  '-o', 'StrictHostKeyChecking = yes',
                  '-o', 'PreferredAuthentications = publickey']
        if self.port != 22:
            prefix.extend(('-p', str(self.port)))
        if self.login_name != _get_current_username():
            prefix.extend(('-l', self.login_name))
        if ('stdin' not in kwargs or kwargs['stdin'] is None) \
           and ('input' not in kwargs or kwargs['input'] is None):
            prefix.append('-n')
        prefix.append(self._hostname)

        login_user_process_runner = None
        if self._sudo_username is not None and self._sudo_password is not None:
            login_user = self._get_login_user()
            login_user_process_runner = ProcessRunner(
                lambda args, **kwargs:
                login_user.run_process_with_public_key_based_ssh(args,
                                                                 **kwargs),
                hostname=self.hostname, login_name=self.login_name,
                sudo_username=self.sudo_username)

        return self._run_process_impl(prefix, args, login_user_process_runner,
                                      **kwargs)

    def check_public_key_based_ssh(self) -> bool:
        process = self.run_process_with_public_key_based_ssh(['whoami'])
        if process.returncode != 0:
            return False
        if self._sudo_username is None:
            expected_stdout = self.login_name
        else:
            expected_stdout = self._sudo_username
        if process.stdout.rstrip('\n') != expected_stdout:
            raise RuntimeError(f'''An error occurred while checking \
public-key-based `ssh' to run a process as `{self}'.
args: {process.args}
stdout: {process.stdout}
stderr: {process.stderr}
returncode: {process.returncode}''')
        return True

    def _check_public_key_based_ssh_to_target_impl(
            self, target: 'UserOnServer') -> subprocess.CompletedProcess:
        args = ['ssh', '-o', 'BatchMode = yes',
                '-o', 'StrictHostKeyChecking = yes',
                '-o', 'PreferredAuthentications = publickey']
        if target.port != 22:
            args.extend(('-p', str(target.port)))
        if self._sudo_username is None \
           and target.login_name != self.login_name:
            args.extend(('-l', target.login_name))
        elif self._sudo_username is not None \
                and target.login_name != self._sudo_username:
            args.extend(('-l', target.login_name))
        args.append('-n')
        args.append(target.hostname)

        if target.sudo_username is None:
            args.append('whoami')
            return self.run_process_with_public_key_based_ssh(args)

        if target.sudo_password is None:
            args.extend(('sudo', '-nkHu', target.sudo_username, '--',
                         'whoami'))
            return self.run_process_with_public_key_based_ssh(args)

        target_process_runner = ProcessRunner(
            lambda args, **kwargs:
            target.run_process_with_public_key_based_ssh(args, **kwargs),
            hostname=self.hostname, login_name=self.login_name,
            sudo_username=self.sudo_username)

        with TemporaryAskpassFile(target_process_runner,
                                  target.sudo_password) as sudo_askpass_file:
            args.extend(('env', f'SUDO_ASKPASS={sudo_askpass_file.path}',
                         'sudo', '-nAkHu', target.sudo_username, '--',
                         'whoami'))
            return self.run_process_with_public_key_based_ssh(args)

    def check_public_key_based_ssh_to_target(self,
                                             target: 'UserOnServer') -> bool:
        process = self._check_public_key_based_ssh_to_target(target)
        if process.returoncode != 0:
            return False
        if target.sudo_username is None:
            expected_stdout = target.login_name
        else:
            expected_stdout = target.sudo_username
        if process.stdout.rstrip('\n') != expected_stdout:
            raise RuntimeError(f'''An error occurred while checking \
public-key-based `ssh' from `{self}' to `{target}'.
args: {process.args}
stdout: {process.stdout}
stderr: {process.stderr}
returncode: {process.returncode}''')
        return True


Authorizee = NewType('Authorizee', Union[None, PublicKey, UserOnServer])

Authentication = NewType('Authentication', Tuple[Authorizee, UserOnServer])


class ConfigParser(object):
    _PUBLIC_KEY = {
        "type": "string",
        "pattern": "^(?:ssh-dss|ssh-rsa|ecdsa-sha2-nistp256|\
ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519) [A-Za-z0-9+/]*=*(?: .*)?$"
    }

    _INDIRECT_PUBLIC_KEY = {
        "type": "object",
        "properties": {"variable": {"type": "string"}},
        "required": ["variable"],
        "additionalProperties": False
    }

    _POSSIBLY_INDIRECT_PUBLIC_KEY = {
        "oneOf": [_PUBLIC_KEY, _INDIRECT_PUBLIC_KEY]
    }

    _USERNAME = {
        "type": "string",
        "pattern": "^[A-Za-z_][0-9A-Za-z_-]*\\$?$"
    }

    _INDIRECT_USERNAME = {
        "type": "object",
        "properties": {"variable": {"type": "string"}},
        "required": ["variable"],
        "additionalProperties": False
    }

    _POSSIBLY_INDIRECT_USERNAME = {
        "oneOf": [_USERNAME, _INDIRECT_USERNAME]
    }

    _INDIRECT_PASSWORD = {
        "type": "object",
        "properties": {"variable": {"type": "string"}},
        "required": ["variable"],
        "additionalProperties": False
    }

    _CURRENT_USER = {
        "type": "string",
        "const": "me"
    }

    _AUTHORIZEE_PUBLIC_KEY = {
        "type": "object",
        "properties": {
            "public_key": _PUBLIC_KEY
        },
        "required": ["public_key"],
        "additionalProperties": False
    }

    _HOST = {
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "host_public_key": _POSSIBLY_INDIRECT_PUBLIC_KEY,
            "login_name": _POSSIBLY_INDIRECT_USERNAME,
            "login_password": _INDIRECT_PASSWORD,
            "sudo_username": _POSSIBLY_INDIRECT_USERNAME,
            "sudo_password": _INDIRECT_PASSWORD
        },
        "required": ["host"],
        "additionalProperties": False
    }

    _GROUP = {
        "type": "object",
        "properties": {
            "group": {"type": "string"},
            "host_public_key": _INDIRECT_PUBLIC_KEY,
            "login_name": _POSSIBLY_INDIRECT_USERNAME,
            "login_password": _INDIRECT_PASSWORD,
            "sudo_username": _POSSIBLY_INDIRECT_USERNAME,
            "sudo_password": _INDIRECT_PASSWORD
        },
        "required": ["group"],
        "additionalProperties": False
    }

    _AUTHORIZEES = {
        "oneOf": [
            _CURRENT_USER,
            _AUTHORIZEE_PUBLIC_KEY,
            _HOST,
            _GROUP
        ]
    }

    _AUTHORIZEES_LIST = {
        "oneOf": [
            _AUTHORIZEES,
            {"type": "array", "items": _AUTHORIZEES}
        ]
    }

    _TARGETS = {
        "oneOf": [_HOST, _GROUP]
    }

    _TARGETS_LIST = {
        "oneOf": [
            _TARGETS,
            {"type": "array", "items": _TARGETS}
        ]
    }

    _AUTHENTICATIONS = {
        "type": "object",
        "properties": {
            "from": _AUTHORIZEES_LIST,
            "to": _TARGETS_LIST
        },
        "required": ["from", "to"],
        "additionalProperties": False
    }

    _CONFIG = {
        "oneOf": [
            _AUTHENTICATIONS,
            {"type": "array", "items": _AUTHENTICATIONS}
        ]
    }

    def __init__(self, inventory: AnsibleInventory):
        self._inventory = inventory

    def _parse_public_key(self, spec: str) -> PublicKey:
        return PublicKey.from_string(spec)

    def _parse_indirect_public_key(self, spec: dict, host: str) -> PublicKey:
        varname = spec['variable']
        if not self._inventory.has_host_variable(host, varname):
            print(f"The host variable `{varname}' of the host `{host}' is not \
found in the Ansible inventory.", file=sys.stderr)
            sys.exit(1)
        value = self._inventory.dereference_host_variable(host, varname)
        if not isinstance(value, str):
            print(f"An invalid public key `{value}' is specified by the \
Ansible host variable `{varname}' of the host `{host}'.", file=sys.stderr)
            sys.exit(1)
        return PublicKey.from_string(value)

    def _parse_possibly_indirect_public_key(
            self, spec, host: str) -> PublicKey:
        if isinstance(spec, str):
            return self._parse_public_key(spec)

        return self._parse_indirect_public_key(spec, host)

    def _parse_username(self, spec: str) -> str:
        return spec

    def _parse_indirect_username(self, spec: dict, host: str) -> str:
        varname = spec['variable']
        if not self._inventory.has_host_variable(host, varname):
            print(f"The host variable `{varname}' of the host `{host}' is not \
found in the Ansible inventory.", file=sys.stderr)
            sys.exit(1)
        value = self._inventory.dereference_host_variable(host, varname)
        if not isinstance(value, str):
            print(f"An invalid username `{value}' is specified by the Ansible \
host variable `{varname}' of the host `{host}'.", file=sys.stderr)
            sys.exit(1)
        return value

    def _parse_possibly_indirect_username(self, spec, host: str) -> str:
        if isinstance(spec, str):
            return self._parse_username(spec)

        return self._parse_indirect_username(spec, host)

    def _parse_indirect_password(self, spec: dict, host: str) -> str:
        varname = spec['variable']
        if not self._inventory.has_host_variable(host, varname):
            print(f"The host variable `{varname}' of the host `{host}' is not \
found in the Ansible inventory.", file=sys.stderr)
            sys.exit(1)
        value = self._inventory.dereference_host_variable(host, varname)
        if not isinstance(value, str):
            print(f"An invalid password is specified by the Ansible host \
variable `{varname}' of the host `{host}'.", file=sys.stderr)
            sys.exit(1)
        return value

    def _parse_current_user(self, spec: str) -> None:
        return None

    def _parse_authorizee_public_key(self, spec: dict) -> PublicKey:
        return self._parse_public_key(spec['public_key'])

    def _parse_host(self, spec: dict) -> UserOnServer:
        name = spec['host']
        if not self._inventory.has_host(name):
            print(f"The host `{name}' is not found in the Ansible inventory.",
                  file=sys.stderr)
            sys.exit(1)

        hostname = name
        if self._inventory.has_host_variable(name, 'ansible_host'):
            hostname = self._inventory.dereference_host_variable(
                name, 'ansible_host')
            if not isinstance(hostname, str):
                print(f"An invalid hostname `{hostname}' is specified by the \
Ansible host variable `ansible_host' of the host `{name}'.", file=sys.stderr)
                sys.exit(1)

        port = None
        if self._inventory.has_host_variable(name, 'ansible_port'):
            port = self._inventory.dereference_host_variable(name,
                                                             'ansible_port')
            if not isinstance(port, int):
                print(f"An invalid port number `{port}' is specified by the \
Ansible host variable `ansible_port' of the host `{name}'.", file=sys.stderr)
                sys.exit(1)

        host_public_key = None
        if 'host_public_key' in spec:
            host_public_key = self._parse_possibly_indirect_public_key(
                spec['host_public_key'], name)

        login_name = None
        if self._inventory.has_host_variable(name, 'ansible_user'):
            login_name = self._inventory.dereference_host_variable(
                name, 'ansible_user')
            if not isinstance(login_name, str):
                print(f"An invalid login name `{login_name}' is specified \
by the Ansible host variable `ansible_user' of the host `{name}'.",
                      file=sys.stderr)
                sys.exit(1)
        if 'login_name' in spec:
            login_name = self._parse_possibly_indirect_username(
                spec['login_name'], name)

        login_password = None
        if self._inventory.has_host_variable(name, 'ansible_ssh_pass'):
            login_password = self._inventory.dereference_host_variable(
                name, 'ansible_ssh_pass')
            if not isinstance(login_password, str):
                print(f"An invalid login password is specificed by the \
Ansible host variable `ansible_ssh_pass' of the host `{name}'.",
                      file=sys.stderr)
                sys.exit(1)
        if 'login_password' in spec:
            login_password = self._parse_indirect_password(
                spec['login_password'], name)

        sudo_username = None
        if self._inventory.has_host_variable(name, 'ansible_become_user'):
            sudo_username = self._inventory.dereference_host_variable(
                name, 'ansible_become_user')
            if not isinstance(sudo_username, str):
                print(f"An invalid `sudo' username `{sudo_username}' is \
specified by the Ansible host variable `ansible_become_user' of the host \
`{name}'.",
                      file=sys.stderr)
                sys.exit(1)
        if 'sudo_username' in spec:
            sudo_username = self._parse_possibly_indirect_username(
                spec['sudo_username'], name)

        sudo_password = None
        if self._inventory.has_host_variable(name, 'ansible_become_pass'):
            sudo_password = self._inventory.dereference_host_variable(
                name, 'ansible_become_pass')
            if not isinstance(sudo_password, str):
                print(f"An invalid `sudo' password is specified by the \
Ansible host variable `ansible_become_pass' of the host `{name}'.",
                      file=sys.stderr)
                sys.exit(1)
        if 'sudo_password' in spec:
            sudo_password = self._parse_indirect_password(
                spec['sudo_password'], name)

        return UserOnServer(
            hostname=hostname, port=port, host_public_key=host_public_key,
            login_name=login_name, login_password=login_password,
            sudo_username=sudo_username, sudo_password=sudo_password)

    def _parse_group(self, spec) -> Set[UserOnServer]:
        name = spec['group']
        if not self._inventory.has_group(name):
            print(f"The group `{name}' is not found in the Ansible inventory.",
                  file=sys.stderr)
            sys.exit(1)

        user_on_server_set = set()
        for host in self._inventory.get_group_members(name):
            hostname = host
            if self._inventory.has_host_variable(host, 'ansible_host'):
                hostname = self._inventory.dereference_host_variable(
                    host, 'ansible_host')
                if not isinstance(hostname, str):
                    print(f"An invalid hostname `{hostname}' is specified by \
the Ansible host variable `ansible_host' of the host `{host}'.",
                          file=sys.stderr)
                    sys.exit(1)

            port = None
            if self._inventory.has_host_variable(host, 'ansible_port'):
                port = self._inventory.dereference_host_variable(
                    host, 'ansible_port')
                if not isinstance(port, int):
                    print(f"An invalid port number `{port}' is specified by \
the Ansible host variable `ansible_port' of the host `{host}'.",
                          file=sys.stderr)
                    sys.exit(1)

            host_public_key = None
            if 'host_public_key' in spec:
                host_public_key = self._parse_indirect_public_key(
                    spec['host_public_key'], host)

            login_name = None
            if self._inventory.has_host_variable(host, 'ansible_user'):
                login_name = self._inventory.dereference_host_variable(
                    host, 'ansible_user')
                if not isinstance(login_name, str):
                    print(f"An invalid login name `{login_name}' is specified \
by the Ansible host variable `ansible_user' of the host `{host}'.",
                          file=sys.stderr)
                    sys.exit(1)
            if 'login_name' in spec:
                login_name = self._parse_possibly_indirect_username(
                    spec['login_name'], host)

            login_password = None
            if self._inventory.has_host_variable(host, 'ansible_ssh_pass'):
                login_password = self._inventory.dereference_host_variable(
                    host, 'ansible_ssh_pass')
                if not isinstance(login_password, str):
                    print(f"An invalid login password is specified by the \
Ansible host variable `ansible_ssh_pass' of the host `{host}'.",
                          file=sys.stderr)
                    sys.exit(1)
            if 'login_password' in spec:
                login_password = self._parse_indirect_password(
                    spec['login_password'], host)

            sudo_username = None
            if self._inventory.has_host_variable(host, 'ansible_become_user'):
                sudo_username = self._inventory.dereference_host_variable(
                    host, 'ansible_become_user')
                if not isinstance(sudo_username, str):
                    print(f"An invalid `sudo' username `{sudo_username}' is \
specified by the Ansible host variable `ansible_become_user' of the host \
`{host}'.",
                          file=sys.stderr)
                    sys.exit(1)
            if 'sudo_username' in spec:
                sudo_username = self._parse_possibly_indirect_username(
                    spec['sudo_username'], host)

            sudo_password = None
            if self._inventory.has_host_variable(host, 'ansible_become_pass'):
                sudo_password = self._inventory.dereference_host_variable(
                    host, 'ansible_become_pass')
                if not isinstance(sudo_password, str):
                    print(f"An invalid `sudo' password is specified by the \
Ansible host variable `ansible_become_pass' of the host `{host}'.",
                          file=sys.stderr)
                    sys.exit(1)
            if 'sudo_password' in spec:
                sudo_password = self._parse_indirect_password(
                    spec['sudo_password'], host)

            user_on_server = UserOnServer(hostname, port, host_public_key,
                                          login_name, login_password,
                                          sudo_username, sudo_password)
            user_on_server_set.add(user_on_server)

        return user_on_server_set

    def _parse_authorizees(self, spec) -> Set[Authorizee]:
        if isinstance(spec, str):
            return set([self._parse_current_user(spec)])

        if 'public_key' in spec:
            return set([self._parse_authorizee_public_key(spec)])

        if 'host' in spec:
            return set([self._parse_host(spec)])

        return self._parse_group(spec)

    def _parse_authorizees_list(self, spec) -> Set[Authorizee]:
        if isinstance(spec, list):
            authorizees = set()
            for elem in spec:
                authorizees.update(self._parse_authorizees(elem))
            return authorizees
        return self._parse_authorizees(spec)

    def _parse_targets(self, spec) -> Set[UserOnServer]:
        if 'host' in spec:
            return set([self._parse_host(spec)])

        return self._parse_group(spec)

    def _parse_targets_list(self, spec) -> Set[UserOnServer]:
        if isinstance(spec, dict):
            return self._parse_targets(spec)

        targets = set()
        for elem in spec:
            targets.update(self._parse_targets(elem))
        return targets

    def _parse_authentications(self, spec) -> Set[Authentication]:
        authorizees = self._parse_authorizees_list(spec['from'])
        targets = self._parse_targets_list(spec['to'])
        authentications = set()
        for authorizee in authorizees:
            for target in targets:
                authentications.add((authorizee, target))
        return authentications

    def parse(self, config_file_path: pathlib.Path) -> Set[Authentication]:
        with open(config_file_path) as config_file:
            if str(config_file_path).endswith('.json'):
                config = json.load(config_file)
            elif str(config_file_path).endswith('.yaml'):
                config = yaml.load(config_file)
            else:
                print(f"An unsupported config file type `{config_file_path}'.",
                      file=sys.stderr)
                sys.exit(1)

        try:
            jsonschema.validate(config, self._CONFIG)
        except jsonschema.exceptions.ValidationError:
            print(f"Failed to parse the config file `{config_file_path}'.",
                  file=sys.stderr)
            sys.exit(1)

        if isinstance(config, dict):
            return self._parse_authentications(config)

        authentications = set()
        for elem in config:
            authentications.update(self._parse_authentications(elem))
        return authentications


def _get_home_dir(process_runner: ProcessRunner) -> pathlib.Path:
    process = process_runner.run(['bash', '-c', 'cd && pwd'])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to get the home \
directory.")
    return pathlib.Path(process.stdout.rstrip('\n'))


def _exists(process_runner: ProcessRunner, path: pathlib.Path) -> bool:
    if not path.is_absolute():
        raise RuntimeError("`path' must be absolute.")

    process = process_runner.run(
        ['bash', '-c', f'[[ -e {path} ]]; echo -n $?'])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to check whether \
`{process_runner.print_path(path)}' exists.")
    return process.stdout == '0'


def _is_file(process_runner: ProcessRunner, path: pathlib.Path) -> bool:
    if not path.is_absolute():
        raise RuntimeError("`path' must be absolute.")

    process = process_runner.run(
        ['bash', '-c', f'[[ -f {path} ]]; echo $?'])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to check whether \
`{process_runner.print_path(path)}' is a file.")
    return process.stdout.rstrip('\n') == '0'


def _is_directory(process_runner: ProcessRunner, path: pathlib.Path) -> bool:
    if not path.is_absolute():
        raise RuntimeError("`path' must be absolute.")

    process = process_runner.run(
        ['bash', '-c', f'[[ -d {path} ]]; echo $?'])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to check whether \
`{process_runner.print_path(path)}' is a directory.")
    return process.stdout.rstrip('\n') == '0'


def _create_parents(process_runner: ProcessRunner, path: pathlib.Path,
                    mode: Optional[str] = None) -> None:
    path = path.resolve().parent
    if _is_directory(process_runner, path):
        return

    args = ['bash', '-c', f"umask 0000 && mkdir -m '{mode}' -p '{path}'"]
    process = process_runner.run(args)
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to create the parent \
directories of `{process_runner.print_path(path)}'.")
    _print_info(f"Created the parent directories of \
`{process_runner.print_path(path)}'.")


def _get_supported_keytypes(process_runner: ProcessRunner) -> Set[Keytype]:
    process = process_runner.run(['ssh', '-Q', 'key'])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to check supported \
keytypes.")

    supported_keytypes = set()
    for line in process.stdout.rstrip('\n').splitlines():
        if line == 'ssh-dss':
            supported_keytypes.add(Keytype('dsa'))
            continue
        if line == 'ssh-rsa':
            supported_keytypes.add(Keytype('rsa'))
            continue
        if line in ('ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                    'ecdsa-sha2-nistp521'):
            supported_keytypes.add(Keytype('ecdsa'))
            continue
        if line == 'ssh-ed25519':
            supported_keytypes.add(Keytype('ed25519'))
            continue
    return supported_keytypes


def _get_host_public_keys(process_runner: ProcessRunner) -> Set[PublicKey]:
    supported_keytypes = _get_supported_keytypes(process_runner)

    host_public_keys = set()
    for path, keytype in (
            ('/etc/ssh/ssh_host_rsa_key.pub', Keytype('rsa')),
            ('/etc/ssh/ssh_host_ecdsa_key.pub', Keytype('ecdsa')),
            ('/etc/ssh/ssh_host_ed25519_key.pub', Keytype('ed25519'))):
        if keytype not in supported_keytypes:
            continue

        process = process_runner.run(['cat', path])
        if process.returncode != 0 or process.stderr != '':
            raise RuntimeError(f"`{process_runner}' failed to get the host \
public key `{process_runner.print_path(path)}'.")
        host_public_keys.add(
            PublicKey.from_string(process.stdout.rstrip('\n')))
    return host_public_keys


def _get_user_known_hosts_file_path(process_runner: ProcessRunner,
                                    target_hostname: str) -> pathlib.Path:
    home_dir = _get_home_dir(process_runner)

    process = process_runner.run(['ssh', '-G', target_hostname])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to check the path to \
the known hosts file.")

    paths = []
    for line in process.stdout.rstrip('\n').splitlines():
        m = re.search('^userknownhostsfile (.+)$', line)
        if m is None:
            continue
        if len(paths) > 0:
            raise RuntimeError("The keyword `userknownhostsfile' appears \
multiple times in the output of the command `ssh -G'.")
        arg = m[1]
        while len(arg) > 0:
            if arg.startswith('"'):
                m = re.search('^"(.*?)"(?: |$)', args)
                if m is None:
                    raise RuntimeError("An invalid argument for the keyword \
`userknownhostsfile' in the output of the command `ssh -G'.")
                if m[1].startswith('~') and not m[1].startswith('~/'):
                    raise RuntimeError("An unsupported tilde expression.")
                path = re.sub('^~', str(home_dir).replace('\\', '\\\\'), m[1])
                paths.append(pathlib.Path(path))
                arg = arg[m.end():]
                continue
            end = arg.find(' ')
            if end == -1:
                if arg.startswith('~') and not arg.startswith('~/'):
                    raise RuntimeError("An unsupported tilde expression.")
                path = re.sub('^~', str(home_dir).replace('\\', '\\\\'), arg)
                paths.append(pathlib.Path(path))
                break
            if arg[:end].startswith('~') and not arg[:end].startswith('~/'):
                raise RuntimeError("An unsupported tilde expression.")
            path = re.sub('^~', str(home_dir).replace('\\', '\\\\'), arg[:end])
            paths.append(pathlib.Path(path))
            arg = arg[end + 1:]
    if len(paths) == 0:
        raise RuntimeError("Failed to check the path to the known hosts \
file.")
    return paths[0]


def _get_known_host_public_keys(process_runner: ProcessRunner,
                                target_hostname: str) -> Set[PublicKey]:
    hostnames = set()
    hostnames.add(target_hostname)
    for family, t, p, c, sockaddr in socket.getaddrinfo(target_hostname, None):
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        hostnames.add(sockaddr[0])

    known_host_public_keys = set()
    for hostname in hostnames:
        process = process_runner.run(['ssh-keygen', '-F', hostname.lower()])
        if process.returncode != 0:
            continue

        for line in process.stdout.rstrip('\n').splitlines():
            if line.startswith('#'):
                continue
            m = re.search('^(?:@cert-authority|@revoked) (.+)$', line)
            if m is not None:
                line = m[1]
            fields = line.split(' ', 3)
            known_host_public_keys.add(PublicKey.from_fields(fields[1:]))
    return known_host_public_keys


def _get_host_public_key_preference(
        process_runner: ProcessRunner,
        target_hostname: str) -> List[FineGrainedKeytype]:
    process = process_runner.run(['ssh', '-G', target_hostname])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to check preference \
among host public keys.")

    preference = None
    for line in process.stdout.rstrip('\n').splitlines():
        m = re.search('^hostkeyalgorithms (.*)$', line)
        if m is None:
            continue
        if preference is not None:
            raise RuntimeError("The keyword `hostkeyalgorithms' appears \
multiple times in the output of the command `ssh -G'.")
        preference = []
        for algorithm in m[1].split(','):
            if algorithm in ('ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                             'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
                             'ssh-ed25519'):
                preference.append(FineGrainedKeytype(algorithm))
    if len(preference) == 0:
        raise RuntimeError('Failed to check preference among host public \
keys.')
    return preference


def _add_host_public_key(process_runner: ProcessRunner,
                         target_hostname: str,
                         host_public_keys: Set[PublicKey]) -> None:
    known_host_public_keys = _get_known_host_public_keys(
        process_runner, target_hostname)
    for known_host_public_key in known_host_public_keys:
        if known_host_public_key not in host_public_keys:
            raise RuntimeError(f"A \
{known_host_public_key.get_readable_keytype()} host public key for the host \
`{target_hostname}' is found in the known hosts file, but it does not match \
any host public key that exists on the host. This means that, the hostname \
`{target_hostname}' is now referring to a machine different from the \
previous one, or you are under a man-in-the-middle attack. Removing the host \
public key from the known hosts file by executing \
`ssh-keygen -R {target_hostname}' might resolve this issue.")

    for host_public_key in host_public_keys:
        if host_public_key in known_host_public_keys:
            return

    host_public_key_preference = _get_host_public_key_preference(
        process_runner, target_hostname)

    preferred_host_public_key = None
    for keytype in host_public_key_preference:
        for host_public_key in host_public_keys:
            if host_public_key.keytype == keytype:
                preferred_host_public_key = host_public_key
                break
        if preferred_host_public_key is not None:
            break
    if preferred_host_public_key is None:
        raise RuntimeError("A logic error.")

    known_hosts_file_path = _get_user_known_hosts_file_path(process_runner,
                                                            target_hostname)

    _create_parents(process_runner, known_hosts_file_path, '0700')

    args = ['bash', '-c', f"umask 0077 && echo '{target_hostname} \
{preferred_host_public_key}' >>'{known_hosts_file_path}'"]
    process = process_runner.run(args)
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to append a host \
public key to the known hosts file \
`{process_runner.print_path(known_hosts_file_path)}'.")
    _print_info(f"Added the host public key \
`{preferred_host_public_key.get_fingerprint()}' of the host \
`{target_hostname}' to the known hosts file \
`{process_runner.print_path(known_hosts_file_path)}'.")


def _cat_file(process_runner: ProcessRunner, path: pathlib.Path) -> str:
    if not path.is_absolute():
        raise RuntimeError("`path' must be absolute.")

    process = process_runner.run(['cat', str(path)])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to cat the file \
`{process_runner.print_path(path)}'.")
    return process.stdout


def _get_user_identities(process_runner: ProcessRunner,
                         target_hostname: str) -> Set[PublicKey]:
    home_dir = _get_home_dir(process_runner)

    process = process_runner.run(['ssh', '-G', target_hostname])
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError("`{process_runner}' failed to get the path to \
identity files.")

    identity_file_paths = set()
    for line in process.stdout.rstrip('\n').splitlines():
        m = re.search('^identityfile (.*)$', line)
        if m is None:
            continue
        arg = m[1]
        if arg.startswith('"'):
            if len(arg) < 2 or not arg.endswith('"'):
                raise RuntimeError("An invalid argument of the keyword \
`identityfile' in the output from the command `ssh -G' on the host \
`{process_runner.hostname}'.")
            arg = arg[1:-1]
        if arg.startswith('~') and not arg.startswith('~/'):
            raise RuntimeError("An unsupported tilde expression `{args}' is \
found in the value of the keyword `identityfile' in the output from the \
command `ssh -G' on the host `{process_runner.hostname}'.")
        identity_file_path = re.sub(
            '^~', str(home_dir).replace('\\', '\\\\'), arg)
        identity_file_paths.add(pathlib.Path(identity_file_path))

    user_identities = set()
    for identity_file_path in identity_file_paths:
        name = identity_file_path.name
        public_key_file_path = identity_file_path.parent / (name + '.pub')
        identity_file_is_file = _is_file(process_runner, identity_file_path)
        public_key_file_is_file = _is_file(
            process_runner, public_key_file_path)
        if identity_file_is_file or public_key_file_is_file:
            if not identity_file_is_file:
                raise RuntimeError(f"A public identity file \
`{process_runner.print_path(public_key_file_path)}' exists, but its private \
counterpart `{process_runner.print_path(identity_file_path)}' does not.")
            if not public_key_file_is_file:
                raise RuntimeError(f"An identity file \
`{process_runner.print_path(identity_file_path)}' exists, but its public \
counterpart `{process_runner.print_path(public_key_file_path)}' does not.")
            user_identity = _cat_file(process_runner, public_key_file_path)
            user_identities.add(PublicKey.from_string(user_identity))
    return user_identities


def _get_authorized_keys(process_runner: ProcessRunner) -> Set[PublicKey]:
    authorized_keys = set()
    home_dir = _get_home_dir(process_runner)

    for path in (home_dir / '.ssh/authorized_keys',
                 home_dir / '.ssh/authorized_keys2'):
        process = process_runner.run(['cat', str(path)])
        if process.returncode != 0:
            continue
        for line in process.stdout.rstrip('\n').splitlines():
            m = re.search('(?:^| )((?:ssh-dss|ssh-rsa|ecdsa-sha2-nistp256|\
ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519) [^ ]+(?: .*)?)$', line)
            if m is None:
                raise RuntimeError(f"An invalid line `{line}' in the \
authorized keys file `{process_runner.print_path(path)}'.")
            authorized_keys.add(PublicKey.from_string(m[1]))
    return authorized_keys


def _generate_user_identity(
        process_runner: ProcessRunner, keytype: FineGrainedKeytype,
        comment: Optional[str]) -> PublicKey:
    home_dir = _get_home_dir(process_runner)

    args = ['ssh-keygen']
    if keytype == FineGrainedKeytype('ssh-dss'):
        args.extend(('-t', 'dsa'))
        identity_file_path = home_dir / '.ssh/id_dsa'
    elif keytype == FineGrainedKeytype('ssh-rsa'):
        args.extend(('-t', 'rsa'))
        identity_file_path = home_dir / '.ssh/id_rsa'
    elif keytype == FineGrainedKeytype('ecdsa-sha2-nistp256'):
        args.extend(('-t', 'ecdsa', '-b', '256'))
        identity_file_path = home_dir / '.ssh/id_ecdsa'
    elif keytype == FineGrainedKeytype('ecdsa-sha2-nistp384'):
        args.extend(('-t', 'ecdsa', '-b', '384'))
        identity_file_path = home_dir / '.ssh/id_ecdsa'
    elif keytype == FineGrainedKeytype('ecdsa-sha2-nistp521'):
        args.extend(('-t', 'ecdsa', '-b', '521'))
        identity_file_path = home_dir / '.ssh/id_ecdsa'
    elif keytype == FineGrainedKeytype('ssh-ed25519'):
        args.extend(('-t', 'ed25519'))
        identity_file_path = home_dir / '.ssh/id_ed25519'
    else:
        raise RuntimeError(f"An invalid keytype `{keytype}'.")
    args.extend(('-N', ''))
    if comment is not None:
        args.extend(('-C', comment))
    args.extend(('-f', str(identity_file_path)))

    public_key_file_path \
        = identity_file_path.parent / (identity_file_path.name + '.pub')
    if _exists(process_runner, identity_file_path):
        raise RuntimeError(f"Failed to generate the identity file \
`{process_runner.print_path(identity_file_path)}' because the file already \
exists.")
    if _exists(process_runner, public_key_file_path):
        raise RuntimeError(f"Failed to generate the identity file \
`{process_runner.print_path(identity_file_path)}' because the public key file \
`{process_runner.print_path(public_key_file_path)}' already exists.")

    process = process_runner.run(args)
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to generate the \
identity file.")
    if not _exists(process_runner, identity_file_path):
        raise RuntimeError(f"The identity file \
`{process_runner.print_path(identity_file_path)}' is not found after \
successful generation by `ssh-keygen'.")
    if not _exists(process_runner, public_key_file_path):
        raise RuntimeError(f"The public key file \
`{process_runner(public_key_file_path)}' is not found after successful \
generation by `ssh-keygen'.")

    _print_info(f"Generated the identity file \
`{process_runner.print_path(identity_file_path)}' and its public counterpart \
`{process_runner.print_path(public_key_file_path)}'.")

    public_key = _cat_file(process_runner, public_key_file_path)
    return PublicKey.from_string(public_key)


def _authorize_user_identity(process_runner: ProcessRunner,
                             user_identity: PublicKey,
                             key_comment: Optional[str]) -> None:
    home_dir = _get_home_dir(process_runner)
    authorized_keys_file_path = home_dir / '.ssh/authorized_keys'

    _create_parents(process_runner, authorized_keys_file_path, '0700')

    if key_comment is not None:
        line = f'{user_identity.keytype} {user_identity.key} {key_comment}'
    else:
        line = f'{user_identity}'
    args = ['bash', '-c',
            f"umask 0077 && echo '{line}' >>'{authorized_keys_file_path}'"]
    process = process_runner.run(args)
    if process.returncode != 0 or process.stderr != '':
        raise RuntimeError(f"`{process_runner}' failed to add a public key to \
the authorized keys file \
`{process_runner.print_path(authorized_keys_file_path)}'.")
    _print_info(f"Authorized the public key \
`{user_identity.get_fingerprint()}' to log in to `{process_runner}'.")


def authorize_public_key(target_process_runner: ProcessRunner,
                         public_key: PublicKey, key_comment: str) -> None:
    authorized_keys = _get_authorized_keys(target_process_runner)
    if public_key in authorized_keys:
        _print_info(f"`{public_key.get_fingerprint()}' is already authorized \
to log in to `{target_process_runner}'. Skipped.")
        return

    _authorize_user_identity(target_process_runner, public_key, key_comment)
    _print_info(f"Authorized the public key `{public_key.get_fingerprint()}' \
to log in to `{target_process_runner}'.")


def authorize(user_identity_preference: List[FineGrainedKeytype],
              key_comment: str,
              target_hostname: str,
              authorizee_process_runner: ProcessRunner,
              target_process_runner: ProcessRunner) -> None:
    host_public_keys = _get_host_public_keys(target_process_runner)
    _add_host_public_key(authorizee_process_runner, target_hostname,
                         host_public_keys)

    user_identities = _get_user_identities(authorizee_process_runner,
                                           target_hostname)
    authorized_keys = _get_authorized_keys(target_process_runner)
    if len(user_identities & authorized_keys) > 0:
        return

    preferred_user_identity = None
    if len(user_identities) > 0:
        for keytype in user_identity_preference:
            for user_identity in user_identities:
                if user_identity.keytype == keytype:
                    preferred_user_identity = user_identity
                    break
            if preferred_user_identity is not None:
                break
    if preferred_user_identity is None:
        preferred_user_identity = _generate_user_identity(
            authorizee_process_runner, user_identity_preference[0],
            key_comment)
    _authorize_user_identity(target_process_runner,
                             preferred_user_identity,
                             key_comment)


if __name__ == '__main__':
    options = Options()
    _verbosity = options.verbosity

    inventory = AnsibleInventory(
        options.inventory_file_path, options.ask_vault_pass,
        options.vault_password_file_path)

    config_parser = ConfigParser(inventory)
    authentications = config_parser.parse(options.config_file_path)

    if options.dry_run:
        for authorizee, target in authentications:
            if authorizee is None:
                print(f'{_get_current_username()} => {target}')
            elif isinstance(authorizee, PublicKey):
                print(f'{authorizee.get_fingerprint()} => {target}')
            elif isinstance(authorizee, UserOnServer):
                print(f'{authorizee} => {target}')
            else:
                raise RuntimeError(f"An invalid authorizee: `{authorizee}'.")
        sys.exit(0)

    _print_info('Authorizing the following SSH authetications...')
    for authorizee, target in authentications:
        if authorizee is None:
            _print_info(f'  {_get_current_username()} => {target}')
        elif isinstance(authorizee, PublicKey):
            _print_info(f'  {authorizee.get_fingerprint()} => {target}')
        elif isinstance(authorizee, UserOnServer):
            _print_info(f'  {authorizee} => {target}')
        else:
            raise RuntimeError(f"An invalid authorizee: `{authorizee}'.")
    _print_info('')

    current_user_process_runner = ProcessRunner(
        lambda args, **kwargs: _run_process(args, **kwargs),
        hostname=None, login_name=_get_current_username())

    process_runner = {}
    for authorizee, target in authentications:
        if isinstance(authorizee, UserOnServer):
            process_runner[authorizee] = None
        process_runner[target] = None
    for target in process_runner.keys():
        _print_info(f"Checking which method the current user \
`{_get_current_username()}' can log in to `{target}'... ", end='')
        if target.check_public_key_based_ssh():
            _print_info('public-key-based SSH.')
            process_runner[target] = ProcessRunner(
                lambda args, **kwargs:
                target.run_process_with_public_key_based_ssh(args, **kwargs),
                hostname=target.hostname, login_name=target.login_name,
                sudo_username=target.sudo_username)
            continue

        if options.use_rsh and target.check_rsh():
            _print_info('rsh')
            process_runner[target] = ProcessRunner(
                lambda args, **kwargs:
                target.run_process_with_rsh(args, **kwargs),
                hostname=target.hostname, login_name=target.login_name,
                sudo_username=target.sudo_username)
            continue

        if target.check_password_based_ssh():
            _print_info('password-based SSH.')
            process_runner[target] = ProcessRunner(
                lambda args, **kwargs:
                target.run_process_with_password_based_ssh(args, **kwargs),
                hostname=target.hostname, login_name=target.login_name,
                sudo_username=target.sudo_username)
            continue

        if target.host_public_key is not None:
            print(target.host_public_key)
            known_host_public_keys = _get_known_host_public_keys(
                current_user_process_runner, target.hostname)
            print(known_host_public_keys)
            if target.host_public_key in known_host_public_keys:
                print(f"The current user `{_get_current_username()}' cannot \
log in to `{target}' with any method.", file=sys.stderr)
                sys.exit(1)

            for known_host_public_key in known_host_public_keys:
                if target.host_public_key.get_readable_keytype() \
                   == known_host_public_key.get_readable_keytype():
                    print(f"A {target.host_public_key.get_readable_keytype()} \
host public key `{target.host_public_key.get_fingerprint()}' is specified for \
the host `{target.hostname}', but another host public key \
`{known_host_public_key.get_fingerprint()}' of the same type has been already \
known. This means that, the hostname `{target.hostname}' is now referring to a \
machine different from the previous one, or you are under a man-in-the-middle \
attack. For the former case, removing the host public key from the known hosts \
file by executing `ssh-keygen -R {target.hostname}' would resolve this issue.")
            _add_host_public_key(current_user_process_runner, target.hostname,
                                 set([target.host_public_key]))

            if target.check_public_key_based_ssh():
                _print_info('public-key-based SSH.')
                process_runner[target] = ProcessRunner(
                    lambda args, **kwargs:
                    target.run_process_with_public_key_based_ssh(args, **kwargs),
                    hostname=target.hostname, login_name=target.login_name,
                    sudo_username=target.sudo_username)
                continue

            if target.check_password_based_ssh():
                _print_info('password-based SSH.')
                process_runner[target] = ProcessRunner(
                    lambda args, **kwargs:
                    target.run_process_with_password_based_ssh(args, **kwargs),
                    hostname=target.hostname, login_name=target.login_name,
                    sudo_username=target.sudo_username)
                continue

        print(f"The current user `{_get_current_username()}' cannot log in to \
`{target}' with any method.", file=sys.stderr)
        sys.exit(1)

    for authorizee, target in authentications:
        if authorizee is None:
            if target.check_public_key_based_ssh():
                _print_info(f"The current user `{_get_current_username()}' is \
already althorized to log in to `{target}' with public-key-based SSH. \
Skipped.")
                continue

        if isinstance(authorizee, UserOnServer):
            if authorizee.check_public_key_based_ssh_to_target(target):
                _print_info(f"`{authorizee}' is already althorized to log in \
to `{target}' with public-key-based SSH. Skipped.")
                continue

        if authorizee is None:
            authorizee_process_runner = ProcessRunner(
                lambda args, **kwargs: _run_process(args, **kwargs),
                hostname=None, login_name=_get_current_username(),
                sudo_username=None)
        elif isinstance(authorizee, PublicKey):
            authorize_public_key(process_runner[target], authorizee,
                                 options.key_comment)
            continue
        elif isinstance(authorizee, UserOnServer):
            authorizee_process_runner = process_runner[authorizee]
        else:
            raise RuntimeError

        target_process_runner = process_runner[target]
        authorize(options.user_identity_preference, options.key_comment,
                  target.hostname, authorizee_process_runner,
                  target_process_runner)

        if authorizee is None:
            if target.check_public_key_based_ssh():
                _print_info(f"Confirmed that the current user \
`{_get_current_username()}' was authorized to log in to `{target}' with \
public-key-based SSH.")
                continue
            print(f"Failed to authorize the current user \
`{_get_current_username()}' to log in to `{target}' with \
public-key-based SSH.", file=sys.stderr)
            sys.exit(1)

        assert(isinstance(authorizee, UserOneServer))
        if authorizee.check_public_key_based_ssh_to_target(target):
            _print_info(f"Confirmed that `{authorizee}' was authorized to log \
in to `{target}' with public-key-based SSH.")
        else:
            print(f"Failed to authorize `{authorizee}' to log in to \
`{target}' with public-key-based SSH.", file=sys.stderr)
            sys.exit(1)
