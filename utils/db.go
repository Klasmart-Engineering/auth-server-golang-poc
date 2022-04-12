package utils

import "log"

type DBInterface interface {
	ConnectToDB() interface{}
	UserExists(userID string) bool
}

type DBConnector struct {
	Connector DBInterface
}

type DummyDBConnector struct {
	dbConnection *interface{}
}

func (c DummyDBConnector) ConnectToDB() interface{} {
	return nil
}

func (c DummyDBConnector) UserExists(userID string) bool {
	log.Printf("User ID: %s", userID)
	return true
}