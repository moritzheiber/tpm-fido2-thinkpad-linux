package ctap2

import "fmt"

func RegistrationPrompt(name, id string) string {
	if name == "" || name == id {
		return "Register a passkey for " + id
	}
	return fmt.Sprintf("Register a passkey for %s (%s)", name, id)
}

func AuthenticationPrompt(id string) string {
	return "Sign in to " + id
}
