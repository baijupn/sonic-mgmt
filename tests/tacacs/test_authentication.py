from contextlib import contextmanager

import paramiko
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.tacacs.tacacs_helper import (
    check_tacacs,
    start_tacacs_server,
    stop_tacacs_server,
)
from tests.common.utilities import paramiko_ssh
from tests.tacacs.utils import (
    TIMEOUT_LIMIT,
    change_and_wait_aaa_config_update,
    ssh_run_command,
)


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
]

EMPTY_PASSWORD_USER = "tacacs_empty_password"


def assert_ssh_authentication_fails(remote_ip, username, password):
    try:
        with paramiko_ssh(remote_ip, username, password):
            pytest.fail("SSH authentication unexpectedly succeeded")
    except paramiko.ssh_exception.AuthenticationException:
        pass


@contextmanager
def tacacs_server_outage(ptfhost):
    pytest_assert(
        stop_tacacs_server(ptfhost),
        "Failed to stop the TACACS+ server before the outage test",
    )
    try:
        yield
    finally:
        pytest_assert(
            start_tacacs_server(ptfhost),
            "Failed to restore the TACACS+ server after the outage test",
        )


@pytest.fixture
def local_user_client():
    with paramiko.SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        yield ssh_client


@pytest.fixture
def empty_password_local_user(
        duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell(
        "sudo userdel --remove {}".format(EMPTY_PASSWORD_USER),
        module_ignore_errors=True,
    )
    try:
        duthost.shell(
            "sudo useradd --create-home --shell /bin/bash {}".format(
                EMPTY_PASSWORD_USER))
        duthost.shell("sudo passwd --delete {}".format(EMPTY_PASSWORD_USER))

        shadow_entry = duthost.shell(
            "sudo getent shadow {}".format(EMPTY_PASSWORD_USER))["stdout"]
        pytest_assert(
            shadow_entry.split(":", 2)[1] == "",
            "Failed to create the empty-password regression account",
        )

        yield EMPTY_PASSWORD_USER
    finally:
        duthost.shell(
            "sudo userdel --remove {}".format(EMPTY_PASSWORD_USER),
            module_ignore_errors=True,
        )


def test_strict_tacacs_rejects_local_user(
        duthosts, enum_rand_one_per_hwsku_hostname,
        tacacs_creds, check_tacacs):  # noqa: F811
    """Verify strict TACACS rejects a local-only user while TACACS is available."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    assert_ssh_authentication_fails(
        duthost.mgmt_ip,
        tacacs_creds["local_user"],
        tacacs_creds["local_user_passwd"],
    )


def test_strict_tacacs_rejects_local_user_after_remote_rejection(
        duthosts, enum_rand_one_per_hwsku_hostname,
        tacacs_creds, check_tacacs):  # noqa: F811
    """Verify failthrough does not turn a TACACS rejection into local access."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(
        duthost, "sudo config aaa authentication failthrough enable")

    try:
        assert_ssh_authentication_fails(
            duthost.mgmt_ip,
            tacacs_creds["local_user"],
            tacacs_creds["local_user_passwd"],
        )
    finally:
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication failthrough default")


@pytest.mark.parametrize("failthrough", ["disable", "enable"])
def test_strict_tacacs_rejects_local_user_when_servers_are_unavailable(
        duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
        tacacs_creds, check_tacacs, failthrough):  # noqa: F811
    """Verify a TACACS outage cannot fall through to a non-root local user."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(
        duthost,
        "sudo config aaa authentication failthrough {}".format(failthrough),
    )
    try:
        with tacacs_server_outage(ptfhost):
            assert_ssh_authentication_fails(
                duthost.mgmt_ip,
                tacacs_creds["local_user"],
                tacacs_creds["local_user_passwd"],
            )
    finally:
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication failthrough default")


@pytest.mark.parametrize("failthrough", ["disable", "enable"])
def test_strict_tacacs_rejects_empty_password_user_during_outage(
        duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
        empty_password_local_user, check_tacacs, failthrough):  # noqa: F811
    """Verify strict TACACS rejects an empty-password user during an outage."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(
        duthost,
        "sudo config aaa authentication failthrough {}".format(failthrough),
    )
    try:
        with tacacs_server_outage(ptfhost):
            assert_ssh_authentication_fails(
                duthost.mgmt_ip,
                empty_password_local_user,
                "",
            )
    finally:
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication failthrough default")


def test_tacacs_local_allows_local_user_when_servers_are_unavailable(
        duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
        tacacs_creds, check_tacacs, local_user_client):  # noqa: F811
    """Verify explicit TACACS-to-local fallback works during a TACACS outage."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(
        duthost, "sudo config aaa authentication login tacacs+ local")
    try:
        pytest_assert(
            stop_tacacs_server(ptfhost),
            "Failed to stop the TACACS+ server before the outage test",
        )
        local_user_client.connect(
            duthost.mgmt_ip,
            username=tacacs_creds["local_user"],
            password=tacacs_creds["local_user_passwd"],
            allow_agent=False,
            look_for_keys=False,
            auth_timeout=TIMEOUT_LIMIT,
        )
        exit_code, _, _ = ssh_run_command(
            local_user_client, "show aaa", expect_exit_code=0, verify=True)
        pytest_assert(exit_code == 0)
    finally:
        pytest_assert(
            start_tacacs_server(ptfhost),
            "Failed to restore the TACACS+ server after the outage test",
        )
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication login tacacs+")


def test_tacacs_local_rejects_empty_password_user_during_outage(
        duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
        empty_password_local_user, check_tacacs):  # noqa: F811
    """Verify explicit local fallback still requires a non-empty password."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(
        duthost, "sudo config aaa authentication login tacacs+ local")
    try:
        pytest_assert(
            stop_tacacs_server(ptfhost),
            "Failed to stop the TACACS+ server before the outage test",
        )
        assert_ssh_authentication_fails(
            duthost.mgmt_ip,
            empty_password_local_user,
            "",
        )
    finally:
        pytest_assert(
            start_tacacs_server(ptfhost),
            "Failed to restore the TACACS+ server after the outage test",
        )
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication login tacacs+")
