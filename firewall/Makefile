IMAGE ?= firewall:latest
LAB ?= firewall.clab.yml

.PHONY: build test image run lab lab-test netns-test fmt clippy clean

build:
	cargo build --release

test:
	cargo test

image:
	docker build -t $(IMAGE) .

run: image
	docker run --rm -it --cap-add=NET_RAW -p 8080:8080 -p 2200:2200 \
		-v "$(PWD)/examples/startup.conf:/etc/firewall/firewall.conf:ro" $(IMAGE)

lab: image
	containerlab deploy -t $(LAB)

lab-test:
	IMAGE=$(IMAGE) LAB=$(LAB) ./tests/containerlab-policy.sh

# Exercises the dataplane without containerlab; needs root for netns/veth.
netns-test:
	./tests/network-namespace.sh

fmt:
	cargo fmt

clippy:
	cargo clippy -- -D warnings

clean:
	cargo clean
	rm -rf target
