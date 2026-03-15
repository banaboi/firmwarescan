from db.loader import lookup


def test_canonical_name_match():
    result = lookup("FreeRTOS")
    assert result is not None
    assert result["name"] == "FreeRTOS"


def test_alias_match():
    result = lookup("freertos-kernel")
    assert result is not None
    assert result["name"] == "FreeRTOS"


def test_normalised_separators_match():
    assert lookup("freertos_kernel")["name"] == "FreeRTOS"
    assert lookup("freertos.kernel")["name"] == "FreeRTOS"
    assert lookup("FreeRTOS Kernel")["name"] == "FreeRTOS"


def test_case_insensitive_match():
    assert lookup("FREERTOS")["name"] == "FreeRTOS"
    assert lookup("mbedtls")["name"] == "Mbed TLS"
    assert lookup("MBEDTLS")["name"] == "Mbed TLS"


def test_returns_cpe_template():
    result = lookup("FreeRTOS")
    assert result["cpe_template"] == "cpe:2.3:o:amazon:freertos:{version}:*:*:*:*:*:*:*"


def test_null_cpe_component():
    result = lookup("littlefs")
    assert result is not None
    assert result["cpe_template"] is None
    assert result["cpe_vendor"] is None


def test_fatfs_null_cpe():
    result = lookup("FatFs")
    assert result is not None
    assert result["cpe_template"] is None


def test_unknown_component_returns_none():
    assert lookup("some-unknown-lib") is None
    assert lookup("") is None


def test_all_known_components_resolve():
    known = [
        "FreeRTOS", "mbedtls", "lwip", "u-boot",
        "zephyr", "openssl", "wolfssl", "littlefs",
        "fatfs", "libcoap",
    ]
    for name in known:
        assert lookup(name) is not None, f"expected {name!r} to resolve"


def test_returned_dict_has_required_keys():
    result = lookup("lwip")
    for key in ("name", "cpe_vendor", "cpe_product", "cpe_part",
                "cpe_template", "version_patterns", "cmake_fetch_names", "notes"):
        assert key in result
