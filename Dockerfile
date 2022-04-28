FROM golang:1.16-alpine as build
WORKDIR /app

COPY ./ ./

RUN go mod download
RUN go build -o /kidsloop-auth-server

FROM alpine

WORKDIR /usr/src/app

ARG USERNAME=kidsloop
ARG USER_UID=1000

COPY --from=build /kidsloop-auth-server .
EXPOSE 8080

RUN adduser -S -D -H -u $USER_UID $USERNAME
USER $USERNAME

CMD ["/usr/src/app/kidsloop-auth-server"]