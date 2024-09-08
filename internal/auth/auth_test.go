package auth

import (
  "net/http"
  "testing"
  "fmt"
)

func TestGetApiKeyOkHeader(t *testing.T) {
  //Ok headers
  headers := make(http.Header)
  in_key := "12345678910abcdefgh"
  headers["Authorization"] = []string{fmt.Sprintf("ApiKey %s", in_key)}
  out_key, err := GetAPIKey(headers)
  if err != nil {
    t.Fatalf("Did not expect error: \"%v\"", err)
  }
  if in_key != out_key {
    t.Fatalf("in_key \"%s\" != out_key \"%s\"", in_key, out_key)
  }
}

func TestGetApiKeyNoAuth(t *testing.T) {
  //No Header
  headers := make(http.Header)
  _, err := GetAPIKey(headers)
  if err == nil {
    t.Fatalf("Expected to return err. No error returned")
  }
  if err != ErrNoAuthHeaderIncluded {
    t.Fatalf("The error expected was \"%v\" but got \"%v\" instead.", ErrNoAuthHeaderIncluded, err)
  } 
}

func TestGetApiKeyMalformedKey(t *testing.T) {
  t.Fatalf("Intentional Fail: Testing CI")
  //Malformed
  headers := make(http.Header)
  in_key := "12345678910abcdefgh"
  headers["Authorization"] = []string{fmt.Sprintf("WrongKey %s", in_key)}
  _, err := GetAPIKey(headers)
  if err == nil {
    t.Fatalf("Expected to return err. No error returned")
  }
  if err !=  ErrMalformedAuthorization {
    t.Fatalf("Expected error \"%v\" but got \"%v\"", ErrMalformedAuthorization, err)
  }
}

func TestGetApiKeyMalformedArr(t *testing.T) {
  //Malformed
  headers := make(http.Header)
  headers["Authorization"] = []string{"ApiKey"}
  _, err := GetAPIKey(headers)
  if err == nil {
    t.Fatalf("Expected to return err. No error returned")
  }
  if err !=  ErrMalformedAuthorization {
    t.Fatalf("Expected error \"%v\" but got \"%v\"", ErrMalformedAuthorization, err)
  }
}
