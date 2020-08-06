TARGET ?= "hostsfile"  # recvfrom

build:
	@$(MAKE) $@ -C $(TARGET)

test:
	@$(MAKE) $@ -C $(TARGET)

clean:
	@$(MAKE) $@ -C $(TARGET)
