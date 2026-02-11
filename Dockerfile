FROM golang:latest
WORKDIR /app
COPY ./go/ .
RUN go get github.com/mattn/go-sqlite3
RUN go mod download
RUN go build -o main ./cmd/main.go
EXPOSE 3000
CMD ["./main"]