FROM golang:1.16-alpine as build
WORKDIR /app

COPY ./ ./

RUN go mod download
RUN go build -o /kidsloop-auth-server

FROM alpine

WORKDIR /usr/src/app

COPY --from=build /kidsloop-auth-server .
EXPOSE 8080

CMD ["/usr/src/app/kidsloop-auth-server"]