include /usr/share/selinux/devel/Makefile

semodule_name = authlogin_duo

$(semodule_name).pp: $(semodule_name).te

semoduledir = @datadir@/selinux/packages

semodule_DATA = $(semodule_name).pp

semodule-activate:
	semodule -i $(DESTDIR)$(semoduledir)/selinux/packages/$(semodule_name).pp

semodule-deactivate:
	semodule -r $(semodule_name)

clean-local:
	rm -f $(semodule_name).fc $(semodule_name).if

EXTRA_DIST = $(semodule_name).te
