from datetime import date

import pytest

from pwn_broker.paths import box_folder_name, safe_name


def test_safe_name():
    assert safe_name("My Box") == "my-box"
    assert safe_name("../etc") == "etc"
    assert safe_name("dc01.forest.htb") == "dc01.forest.htb"
    assert safe_name("10.10.10.161") == "10.10.10.161"
    assert safe_name("a_b") == "a-b"
    with pytest.raises(ValueError):
        safe_name("///")


def test_box_folder_name():
    assert box_folder_name(date(2026, 11, 14), "HTB", "Forest") == "2026-11-14_htb_forest"
