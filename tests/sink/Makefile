.PHONY: all dev prepare start

IMAGENAME := sink

all : build start

build:
	@docker build -t ${IMAGENAME}:latest -f Dockerfile .

start: build
	@docker run --rm -d \
		-p 3306:3306 \
		-v /etc/localtime:/etc/localtime:ro \
		${IMAGENAME}:latest

access:
	docker exec -it $(shell docker ps | grep ${IMAGENAME} | awk '{split($$0,a," "); print a[1]}') /bin/bash

stop:
	@if [ $(shell docker ps -f status=running | grep ${IMAGENAME} | head -n1 | wc -l) -eq 0 ]; then \
			echo "[+] Instance $(shell docker ps -a | grep ${IMAGENAME} | head -n1 | awk '{split($$0,a," "); print a[1]}') of image ${IMAGENAME} was found but is not running." ;\
	else \
			echo "[+] Stopping instance $(shell docker ps -a | grep ${IMAGENAME} | head -n1 | awk '{split($$0,a," "); print a[1]}') of image ${IMAGENAME} ..." ;\
			docker stop $(shell docker ps -a | grep ${IMAGENAME} | head -n1 | awk '{split($$0,a," "); print a[1]}') ;\
			echo "[+] Done !"; \
	fi
