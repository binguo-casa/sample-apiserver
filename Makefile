IMG ?= kube-sample-apiserver:latest

.PHONY: all
all: build

.PHOHY: test
test:
	go test ./... -coverprofile cover.out

.PHOHY: vet
vet:
	go vet ./...

.PHONY: build
build: vet
	#go build -a -o artifacts/simple-image/kube-sample-apiserver
	go build -o artifacts/simple-image/kube-sample-apiserver

.PHONY: docker-build
docker-build: build
	docker build -t ${IMG} artifacts/simple-image

.PHONY: docker-push
docker-push:
	docker push ${IMG}

.PHONY: kustomize
kustomize:
	cd artifacts/example && kustomize edit set image kube-sample-apiserver=${IMG}
	kustomize build artifacts/example

.PHONY: deploy
deploy:
	cd artifacts/example && kustomize edit set image kube-sample-apiserver=${IMG}
	kustomize build artifacts/example | kubectl apply -f -

.PHONY: undeploy
undeploy:
	cd artifacts/example && kustomize edit set image kube-sample-apiserver=${IMG}
	kustomize build artifacts/example | kubectl delete --ignore-not-found -f -
