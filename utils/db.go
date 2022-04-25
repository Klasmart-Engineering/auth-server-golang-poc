package utils

import (
	"github.com/google/uuid"
	"log"
)

type DBConnector interface {
	ConnectToDB() interface{}
	UserExists(userID string) bool
}

type DummyDBConnector struct {
	dbConnection *interface{}
}

func (c DummyDBConnector) ConnectToDB() interface{} {
	return nil
}

func (c DummyDBConnector) UserExists(userID string) bool {
	if _, err := uuid.Parse(userID); err == nil {
		log.Printf("User ID: %s", userID)
		return true
	} else {
		return false
	}
}