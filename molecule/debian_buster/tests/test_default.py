"""Molecule Default Intgration Test"""
import os
import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']
).get_hosts('all')


def test_hosts_file(host):
    f = host.file('/etc/ssh/sshd_config')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.mode == 0o644


def test_service(host):
    s = host.service('sshd')

    assert s.is_running
    assert s.is_enabled


def test_socket(host):
    s_ipv4 = host.socket('tcp://0.0.0.0:22')
    s_ipv6 = host.socket('tcp://:::22')

    assert s_ipv4.is_listening
    assert s_ipv6.is_listening


def test_package(host):
    p = host.package('openssh-server')

    assert p.is_installed
