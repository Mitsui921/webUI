base_path := $(shell pwd)

default:
	$(error Please specify a make target (see README.md ; QuickStart:make deps-env && make build))

deps-env:
	test -d ngsdn-tutorial || git clone -b master https://github.com/opennetworkinglab/ngsdn-tutorial
	cd ngsdn-tutorial && make pull-deps

build:
	@mkdir build
	cp src/datapath/upf.p4 ngsdn-tutorial/p4src/main.p4
	cp src/datapath/parse.p4 ngsdn-tutorial/p4src/parse.p4
	cp src/datapath/ingress.p4 ngsdn-tutorial/p4src/ingress.p4
	cp src/datapath/engress.p4 ngsdn-tutorial/p4src/engress.p4
	cp src/datapath/NDNCore.p4 ngsdn-tutorial/p4src/NDNCore.p4
	cp src/datapath/defs.p4 ngsdn-tutorial/p4src/defs.p4

	cd ${base_path}/ngsdn-tutorial && make p4-build
	cp ngsdn-tutorial/p4src/build/bmv2.json build/
	cp ngsdn-tutorial/p4src/build/p4info.txt build/
	cd src/control/ && go build -o cp-upf main.go && mv cp-upf ${base_path}/build
	#cp test_script/send_gtp_uplink.py ./ngsdn-tutorial/mininet/
	#cp test_script/send_udp_downlink.py ./ngsdn-tutorial/mininet/
clean:
	@rm -rf build
	#@rm -f ./ngsdn-tutorial/mininet/send_gtp_uplink.py
	#@rm -f ./ngsdn-tutorial/mininet/send_udp_downlink.py


