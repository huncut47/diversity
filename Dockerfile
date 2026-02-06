FROM golang:latest
WORKDIR /app
COPY ./go . .
RUN go mod download
RUN go build -o main ./cmd/main.go
EXPOSE 3000
CMD ["./main"]