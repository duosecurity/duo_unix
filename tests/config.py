#!/usr/bin/env python3
from tempfile import NamedTemporaryFile
from textwrap import dedent


class DuoUnixConfig(dict):
    def __str__(self):
        config = dedent(
            """
        [duo]\n
        """
        )
        for key in self:
            config += "{key} = {value}\n".format(key=key, value=self[key])
        return config

    def failmode_as_prefix(self):
        failmode = self.get("failmode", "safe")
        if failmode == "safe" or failmode is None:
            return "Failsafe"
        if failmode == "secure":
            return "Failsecure"
        else:
            return "Unknown"


# Referred to as "duo.conf" in cram testing
TESTCONF = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
)

# Referred to as "bad-corrupt.conf" in cram testing
BAD_CORRUPT_CONF = """
[duo]
ikey =
skey =
host =
q3598pjg9jajaf
"""
BAD_CORRUPT_SECURE_CONF = """
[duo]
failmode=secure
ikey =
skey =
host =
q3598pjg9jajaf
"""


# Referred to as "bad-header_only.conf" in cram testing
BAD_HEADER_CONF = """
[duo]
"""

# Referred to as "bad-empty.conf" in cram testing
BAD_EMPTY_CONF = """
"""

# Referred to as "bad-missing_values.conf" in cram testing
BAD_MISSING_VALUES_CONF = """
[duo]
ikey =
skey =
host =
"""

# Referred to as "mockduo_failsecure.conf"
MOCKDUO_FAILSECURE = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    failmode="secure",
)

MOCKDUO_FAILSECURE_BAD_CERT = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="nonexistent/ca.pem",
    failmode="secure",
)

# Referred to as "mockduo.conf"
MOCKDUO_CONF = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
)

# Referred to as "mockduo_noverify.conf"
MOCKDUO_NOVERIFY = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    noverify="1",
)

# Referred to as "mockduo_autopush.conf"
MOCKDUO_AUTOPUSH = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    autopush="yes",
    prompts="1",
)

# Referred to as "mockduo_badkeys.conf"
MOCKDUO_BADKEYS = DuoUnixConfig(
    ikey="foo",
    skey="bar",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
)

MOCKDUO_BADKEYS_FAILSECURE = DuoUnixConfig(
    ikey="foo",
    skey="bar",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    failmode="secure",
)

# Referred to as "mockduo_fallback.conf" in cram tests
MOCKDUO_FALLBACK = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    fallback_local_ip="yes",
)

# Referred to as "mockduo_proxy.conf" in cram tests
MOCKDUO_PROXY = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    http_proxy="http://localhost:8888/",
)

MOCKDUO_FIPS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    dev_fips_mode="true",
    cafile="certs/mockduo-ca.pem",
    noverify="1",
)

# Referred to as "duo.conf" in the cram tests
DUO_CONF = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
)

# Referred to as "mockduo_prompts_1.conf" in cram tests
MOCKDUO_PROMPTS_1 = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    autopush="yes",
    prompts="1",
)


# Refered to as "mockduo_prompts_default.conf" in cram tests
MOCKDUO_PROMPTS_DEFAULT = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    autopush="true",
)

# Referred to as "mockduo_autopush_secure.conf" in cram tests
MOCKDUO_AUTOPUSH_SECURE = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    autopush="yes",
    prompts="1",
    failmode="secure",
)

MOCKDUO_GECOS_SEND_UNPARSED = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    send_gecos="true",
)

MOCKDUO_GECOS_DEPRECATED_PARSE_FLAG = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_parsed="true",
)

MOCKDUO_GECOS_DEFAULT_DELIM_6_POS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_username_pos="6",
)

MOCKDUO_GECOS_SLASH_DELIM_3_POS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_delim="/",
    gecos_username_pos="3",
)

MOCKDUO_GECOS_LONG_DELIM = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_delim=",,",
)

MOCKDUO_GECOS_INVALID_DELIM_COLON = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_delim=":",
)

MOCKDUO_GECOS_INVALID_DELIM_PUNC = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_delim="a",
)


MOCKDUO_GECOS_INVALID_DELIM_WHITESPACE = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_delim="  ",
)

MOCKDUO_GECOS_INVALID_POS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    gecos_username_pos="-1",
)

# Referred to as "mockduo_users.conf"
MOCKDUO_USERS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    groups="users",
)

MOCKDUO_USERS_ADMINS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    group="users,admin",
)


MOCKDUO_ADMINS_NO_USERS = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    group="admin,!users",
)

MOTD_CONF = DuoUnixConfig(
    ikey="DIXYZV6YM8IFYVWBINCA",
    skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
    host="localhost:4443",
    cafile="certs/mockduo-ca.pem",
    motd="yes",
)

MOCKDUO_EXTRA_SPACE = """
[duo]
ikey = DIXYZV6YM8IFYVWBINCA
skey =
 yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo
host = localhost:4443
cafile = certs/mockduo-ca.pem
 ; This comment shouldn't break Duo
"""


class TempConfig(object):
    def __init__(self, config_data):
        self.config_data = str(config_data)
        self.temp_file = None

    def __enter__(self):
        self.temp_file = NamedTemporaryFile()
        self.temp_file.write(self.config_data.encode("utf8"))
        self.temp_file.flush()
        return self.temp_file

    def __exit__(self, type, value, traceback):
        self.temp_file.close()
