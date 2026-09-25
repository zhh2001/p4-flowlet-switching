P4C ?= p4c-bm2-ss
PYTHON ?= python3

.PHONY: build run test clean

build: build/flowlet.json build/flowlet.p4info.txtpb build/controller

build/flowlet.json build/flowlet.p4info.txtpb &: p4/flowlet.p4
	mkdir -p build
	$(P4C) --std p4-16 --Werror --p4runtime-files build/flowlet.p4info.txtpb -o build/flowlet.json $<

build/controller: $(wildcard controller/*.go) go.mod go.sum
	mkdir -p build
	go build -o $@ ./controller

run: build
	sudo env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) mininet/diamond.py

test: build
	go test ./...
	go vet ./...
	sudo env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

clean:
	rm -rf build mininet/__pycache__ tests/__pycache__
