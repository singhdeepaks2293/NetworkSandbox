IMAGE ?= switch:latest
LAB ?= switch.clab.yml

.PHONY: build test image lab lab-test clean

build:
	cargo build --release

test:
	cargo test

image:
	docker build -t $(IMAGE) .

lab: image
	containerlab deploy -t $(LAB)

lab-test:
	IMAGE=$(IMAGE) LAB=$(LAB) ./tests/containerlab-8021q.sh

clean:
	cargo clean
	rm -rf target
