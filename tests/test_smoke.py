import kinship


def test_wire_version() -> None:
    assert kinship.wire_version() == 1


def test_version_is_a_string() -> None:
    assert isinstance(kinship.__version__, str)
