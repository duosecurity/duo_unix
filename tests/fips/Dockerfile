FROM rockylinux:9

# Install build dependencies and Python test requirements BEFORE FIPS activation
# to avoid any potential pip hashlib issues under FIPS enforcement.
RUN dnf install -y \
        autoconf automake libtool gcc make pkgconfig \
        openssl-devel pam-devel openssl \
        python3.12 python3.12-pip \
    && dnf clean all \
    && pip3.12 install --no-cache-dir pexpect

# Activate OpenSSL FIPS mode (mirrors RHEL fips-mode-setup without kernel fips=1):
# 1. Switch crypto policy to FIPS (generates fips_local.cnf with [fips_sect])
RUN update-crypto-policies --set FIPS

# 2. Replace openssl.cnf: load fips + default + base providers, enforce fips=yes
#    as the default algorithm property. Non-FIPS algorithms are rejected;
#    FIPS-approved algorithms (HMAC-SHA512, AES, SHA-2) route through the
#    FIPS provider.
RUN printf '%s\n' \
        'config_diagnostics = 1' \
        'openssl_conf = openssl_init' \
        '' \
        '.include /etc/pki/tls/fips_local.cnf' \
        '' \
        '[openssl_init]' \
        'providers = provider_sect' \
        'alg_section = algorithm_sect' \
        'ssl_conf = ssl_module' \
        '' \
        '[provider_sect]' \
        'fips = fips_sect' \
        'default = default_sect' \
        'base = base_sect' \
        '' \
        '[default_sect]' \
        'activate = 1' \
        '' \
        '[base_sect]' \
        'activate = 1' \
        '' \
        '[algorithm_sect]' \
        'default_properties = fips=yes' \
        '' \
        '[ssl_module]' \
        'system_default = crypto_policy' \
        '' \
        '[crypto_policy]' \
        '.include = /etc/crypto-policies/back-ends/opensslcnf.config' \
    > /etc/pki/tls/openssl.cnf

# Copy source tree
COPY . /src
WORKDIR /src

CMD ["/src/tests/fips/entrypoint.sh"]
