

# ----------------------------------------
# 	Swift
# ----------------------------------------

start:
	swift run AVAllianceHummingbirdServer


# docker build -t av-alliance-test-image -f Docker/BlogTests.Dockerfile .
# docker run --name av-alliance-test-instance --rm av-alliance-test-image

run:
	swift run App

build:
	swift build

release:
	swift build -c release
	
test:
	swift test --parallel

test-with-coverage:
	swift test --parallel --enable-code-coverage

clean:
	rm -rf .build

# ----------------------------------------
# 	System
# ----------------------------------------

install: release
	install ./.build/release/App /usr/local/bin/App

uninstall:
	rm /usr/local/bin/App

# ----------------------------------------
# 	Docker
# ----------------------------------------

docker-build:
	docker build \
		-t av-alliance-image \
		-f ./docker/AVAlliance.Dockerfile \
		.

docker-run: docker-build
	docker run \
		--name av-alliance \
		-v $(PWD)/:/app \
		-w /app \
		-e "PS1=\u@\w: " \
		-p 8080:8080 \
		--rm \
		-it av-alliance-image

docker-clean:
	docker rmi av-alliance-image

# swift-format commands

format:
	swift-format -i -r ./Sources && swift-format -i -r ./Tests

lint:
	swift-format lint -r ./Sources && swift-format lint -r ./Tests

openapi-server:
	#docker run -p 8888:8080 -e SWAGGER_JSON=/mnt/openapi.yaml -v ./OpenAPI:/mnt swaggerapi/swagger-ui
	docker run --rm --name "openapi-server" \
-v "$(PWD)/OpenAPI:/usr/share/nginx/html" \
-p 8888:80 nginx

openapi-validate:
	docker run --rm --name "openapi-validate" \
-v "$(PWD)/OpenAPI/openapi.yaml:/openapi.yaml" \
pythonopenapi/openapi-spec-validator /openapi.yaml

openapi-security-check:
	docker run --rm --name "openapi-security-check" \
-v "$(PWD)/OpenAPI:/app" \
-t owasp/zap2docker-weekly zap-api-scan.py \
-t /app/openapi.yaml -f openapi


