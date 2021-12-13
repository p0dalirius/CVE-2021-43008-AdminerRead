.PHONY: all dev prepare start

all : build start

build:
	@docker build -t tmp:latest -f Dockerfile .

start: build
	@docker run -d \
		-p 80:80 -p 443:443 \
		-v /etc/localtime:/etc/localtime:ro \
		tmp:latest

access:
	docker exec -it $(shell docker ps | grep tmp | awk '{split($$0,a," "); print a[1]}') /bin/bash

stop:
	@if [ $(shell docker ps -f status=running | grep tmp | head -n1 | wc -l) -eq 0 ]; then \
			echo "[+] Instance $(shell docker ps -a | grep tmp | head -n1 | awk '{split($$0,a," "); print a[1]}') of image tmp was found but is not running." ;\
	else \
			echo "[+] Stopping instance $(shell docker ps -a | grep tmp | head -n1 | awk '{split($$0,a," "); print a[1]}') of image tmp ..." ;\
			docker stop $(shell docker ps -a | grep ${IMAGE} | head -n1 | awk '{split($$0,a," "); print a[1]}') ;\
			echo "[+] Done !"; \
	fi
