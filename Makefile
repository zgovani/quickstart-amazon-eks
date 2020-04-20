.PHONY: build test clean publish

TASKCAT_OPTIONS ?=
VERSION ?=
BUCKET ?=
REGION ?=
PREFIX ?= quickstart-amazon-eks
PROFILE ?= default
GH_RELEASE ?= false

build:
	mkdir -p output/build/functions
	build/lambda_package.sh
	cp -r functions/packages output/build/functions/
	cp -r scripts templates submodules output/build
	cp -r LICENSE.txt NOTICE.txt output/build
	if [ "$(VERSION)" != "" ] ; then \
      sed -i "s|Default: $(PREFIX)/|Default: $(PREFIX)-versions/$(VERSION)/|g" output/build/templates/*.yaml ; \
    fi
	cd output/build/ && zip -X -r ../release.zip .

test:
	mkdir -p taskcat_outputs
	docker build -t quickstart-amazon-eks:build .
	docker run --rm -ti -v \
	  /var/run/docker.sock:/var/run/docker.sock \
	  --mount type=bind,source=${PWD}/taskcat_outputs,target=/src/taskcat_outputs \
	  --mount type=bind,source=${HOME}/.aws,target=~/.aws \
	  --mount type=bind,source=${HOME}/.taskcat.yml,target=~/.taskcat.yml \
	  quickstart-amazon-eks:build \
	  taskcat test run ${TASKCAT_OPTIONS}

publish:
	if [ "$(BUCKET)" == "" ] ; then \
      echo BUCKET must be specified to publish; exit 1; \
    fi
	if [ "$(REGION)" == "" ] ; then \
      echo REGION must be specified to publish; exit 1; \
    fi
	if [ "$(VERSION)" == "" ] ; then \
		cd output/build && aws s3 sync --delete --size-only --profile $(PROFILE) --region $(REGION) ./ s3://$(BUCKET)/$(PREFIX)/ ; \
	else \
	    cd output/build && aws s3 sync --delete --size-only --profile $(PROFILE) --region $(REGION) ./ s3://$(BUCKET)/$(PREFIX)-versions/$(VERSION)/ ; \
	    if [ $(shell echo $(VERSION) | grep -c dev) -eq 0 ] ; then \
	        if [ "$(GH_RELEASE)" == "true" ] ; then \
	        	hub release create -a "../release.zip#$(PREFIX)-s3-package-v$(VERSION).zip" v$(VERSION) ;\
	        fi ; \
	    fi ; \
	fi

clean:
	rm -rf output/
	rm -rf taskcat_outputs
	rm -rf .taskcat
	rm -rf functions/packages
