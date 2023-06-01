package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"

	gcs "github.com/kai-ten/go-csf-schemas"
	"github.com/okta/okta-sdk-golang/v2/okta"
	log "github.com/sirupsen/logrus"
)

type OktaRecord struct {
	UUID                  string                         `json:"uuid"`
	Published             *time.Time                     `json:"published"`
	EventType             string                         `json:"eventType"`
	Version               string                         `json:"version"`
	Severity              string                         `json:"severity"`
	LegacyEventType       string                         `json:"legacyEventType"`
	DisplayMessage        string                         `json:"displayName"`
	Actor                 *okta.LogClient                `json:"actor"`
	Client                *okta.LogClient                `json:"client"`
	Outcome               *okta.LogClient                `json:"outcome"`
	Target                *[]okta.LogTarget              `json:"target"`
	Transaction           *okta.LogTransaction           `json:"transaction"`
	DebugContext          *okta.LogDebugContext          `json:"debugContext"`
	AuthenticationContext *okta.LogAuthenticationContext `json:"authenticationContext"`
	SecurityContext       *okta.LogSecurityContext       `json:"securityContext"`
	Request               *okta.LogRequest               `json:"request"`
}

type Classification struct {
	Object   string
	ObjectID uint8
}

func GetActivityDetails(eventType *string) Classification {
	activity := Classification{
		Object:   "Unknown",
		ObjectID: 0,
	}

	if strings.Contains(*eventType, "user.authentication") {
		return Classification{
			Object:   "Logon",
			ObjectID: 1,
		}
	}
	return activity
}

func GetAuthProtocol(authProvider *string) Classification {
	authProtocol := Classification{
		Object:   "unknown",
		ObjectID: 0,
	}

	if strings.Contains(*authProvider, "FACTOR") {
		return Classification{
			Object:   "other/mfa",
			ObjectID: 99,
		}
	}

	return authProtocol
}

func TransformRecordOkta(oktaRecord *OktaRecord) {
	var authentication gcs.Authentication

	activity := GetActivityDetails(&oktaRecord.EventType)
	authentication.Activity = activity.Object
	authentication.ActivityID = activity.ObjectID

	authProtocol := GetAuthProtocol(&oktaRecord.AuthenticationContext.AuthenticationProvider)
	authentication.AuthProtocol = authProtocol.Object
	authentication.AuthProtocolID = authProtocol.ObjectID
}

func ReadFileOkta(file_key string) error {
	f, err := os.Open(file_key)
	if err != nil {
		log.Errorf("Could not open file. %v", err)
		return err
	}

	file_data := bufio.NewReader(f)

	for {
		var record OktaRecord
		line, err := file_data.ReadBytes('\n')
		if err != nil {
			log.Debugf("Could not read line: %v", err)
			break
		}

		err = json.Unmarshal(line, &record)
		if err != nil {
			log.Errorf("Could not unmarshal JSON log: %v", err)
			return err
		}
		TransformRecordOkta(&record)
	}

	return nil
}
