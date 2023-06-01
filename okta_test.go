package main

import "testing"

func TestGetActivityDetailsLogon(t *testing.T) {
	eventType := "user.authentication.auth_via_mfa"
	activityDetails := GetActivityDetails(&eventType)

	if activityDetails.Object != "Logon" {
		t.Fatalf("Activity did not match expected result: Logon")
	}
	if activityDetails.ObjectID != 1 {
		t.Fatalf("ActivityID did not match expected result: 1")
	}
}

func TestGetActivityDetailsCatchAll(t *testing.T) {
	eventType := "invalid"
	activityDetails := GetActivityDetails(&eventType)

	if activityDetails.Object != "Unknown" {
		t.Fatalf("Activity did not match expected result: Unknown")
	}
	if activityDetails.ObjectID != 0 {
		t.Fatalf("ActivityID did not match expected result: 0")
	}
}

func TestGetAuthProtocolMFA(t *testing.T) {
	authenticationProvider := "FACTOR_PROVIDER"
	authProtocol := GetAuthProtocol(&authenticationProvider)

	if authProtocol.Object != "Other/mfa" {
		t.Fatalf("AuthProtocol did not match expected result: Unknown")
	}
	if authProtocol.ObjectID != 99 {
		t.Fatalf("AuthProtocolID did not match expected result: 0")
	}
}

func TestGetAuthProtocolCatchAll(t *testing.T) {
	authenticationProvider := "invalid"
	authProtocol := GetAuthProtocol(&authenticationProvider)

	if authProtocol.Object != "Unknown" {
		t.Fatalf("AuthProtocol did not match expected result: Unknown")
	}
	if authProtocol.ObjectID != 0 {
		t.Fatalf("AuthProtocolID did not match expected result: 0")
	}
}

func BenchmarkFileRead(b *testing.B) {
	b.ReportAllocs()

	file_key := "./assets/okta-syslog.log"

	for n := 0; n < b.N; n++ {
		if err := ReadFileOkta(file_key); err != nil {
			b.Errorf("Failed to read file: %v", err)
		}
	}
}
