PYTHON = $(shell python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)");

.PHONY: all clean

all: bridges stations

bridges:
    $(PYTHON) bridge.py cs1 8
    $(PYTHON) bridge.py cs2 8
    $(PYTHON) bridge.py cs3 8

stations:
    $(PYTHON) station.py -route ifaces/ifaces_r1.json rtables/rtable_r1.json hosts.json
    $(PYTHON) station.py -route ifaces/ifaces_r2.json rtables/rtable_r2.json hosts.json
    $(PYTHON) station.py -no ifaces/ifaces_a.json rtables/rtable_a.json hosts.json
    $(PYTHON) station.py -no ifaces/ifaces_b.json rtables/rtable_b.json hosts.json
    $(PYTHON) station.py -no ifaces/ifaces_c.json rtables/rtable_c.json hosts.json
    $(PYTHON) station.py -no ifaces/ifaces_d.json rtables/rtable_d.json hosts.json

clean:
    del bridge_cs1.json
    del bridge_cs2.json
    del bridge_cs3.json