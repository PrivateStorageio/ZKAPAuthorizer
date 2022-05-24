# See nixpkgs/nixos/lib/test-driver/test_driver/ for the test driver API.

from test_driver.machine import Machine

from base64 import urlsafe_b64encode

def deterministic_vouchers():
    for i in range(255):
        yield urlsafe_b64encode(bytes(i) * 44)

def test() -> None:
    vouchers = iter(deterministic_vouchers())

    # Get the service running and usable
    boot_vms([replication, recovery, storage])
    wait_for_services(replication, recovery, storage, issuer)

    # Get replication enabled
    acquire_zkaps(next(vouchers), replication, issuer)
    replica_cap = enable_replication(replication)

    # Get some more ZKAPs
    acquire_zkaps(next(vouchers), replication, issuer)

    # Demonstrate that we can recover from the replica
    recover(replication, recovery, replica_cap)


def boot_vms(vms: list[Machine]) -> None:
    for vm in VMs:
        vm.start()


def wait_for_services(replication: Machine, recovery: Machine, storage: Machine, issuer: Machine) -> None:
    replication.wait_for_unit("tahoe.node-c")
    recovery.wait_for_unit("tahoe.node-c")
    server.wait_for_unit("tahoe.introducer-i")
    server.wait_for_unit("tahoe.node-s")
    issuer.wait_for_unit("zkapissuer")


def acquire_zkaps(voucher: str, issuer: Machine, replication: Machine) -> None:
    """
    Fund a voucher at the given issuer and then give it to the indicated
    Tahoe-LAFS node for redemption.
    """
    print(issuer.succeed(
        f"""
        sqlite3 /tmp/issuer.sqlite3 "INSERT INTO
        """
    ))
    print(replication.succeed(
        f"""
        curl --data '{{"voucher": {voucher!r}}}' http://localhost:3456/storage-plugins/privatestorageio-zkapauthz-v1/voucher
        """
    ))
