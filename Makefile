APP_NAME := localscan
DIST_DIR := dist

.PHONY: build all clean

build:
	go build -o $(APP_NAME) .

all: clean
	@mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64 go build -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe .
	@echo "Build complete. Binaries in $(DIST_DIR)/"

clean:
	rm -rf $(DIST_DIR)
	rm -f $(APP_NAME)
