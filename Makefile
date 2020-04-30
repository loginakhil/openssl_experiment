BUILD_ID=1
.PHONY: all
all:
	@echo "Building ...."
	@g++ -std=c++11 \
		-Wno-deprecated \
		-I/usr/local/opt/openssl/include main.cpp \
		-L/usr/local/opt/openssl/lib/ \
		-l ssl \
		-l crypto \
		-o main.exe

.PHONY: test
test: all
	@echo "Generating certs"
	$(shell bash generate_test_cert.sh)
	@echo "Verifying certs"
	./main.exe cert.pem

.PHONY: docker
docker:
	@echo "building and starting the container ..."
	@docker build --rm --force-rm -t openssl_test:$(BUILD_ID) . -f Dockerfile
	@docker run -it openssl_test:$(BUILD_ID) bash

