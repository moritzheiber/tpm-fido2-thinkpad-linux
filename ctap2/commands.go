package ctap2

// CTAP2 command bytes
const (
	CmdMakeCredential   = 0x01
	CmdGetAssertion     = 0x02
	CmdGetInfo          = 0x04
	CmdClientPIN        = 0x06
	CmdGetNextAssertion = 0x08
)

// CTAP2 status codes
const (
	StatusSuccess              = 0x00
	StatusInvalidCommand       = 0x01
	StatusInvalidParameter     = 0x02
	StatusInvalidCBOR          = 0x12
	StatusCredentialExcluded   = 0x19
	StatusUnsupportedAlgorithm = 0x26
	StatusOperationDenied      = 0x27
	StatusNoCredentials        = 0x2E
	StatusUserActionTimeout    = 0x2F
	StatusNotAllowed           = 0x30
	StatusPINNotSet            = 0x35
	StatusOther                = 0x7F
)

// COSE algorithm identifiers
const (
	COSEAlgES256 = -7  // ECDSA with SHA-256
	COSEAlgECDH  = -25 // ECDH-ES + HKDF-256 (used for key agreement)
)

// CTAP2 extension error codes
const (
	StatusExtensionFirst = 0xE0 // First extension-defined error
)

// COSE key type identifiers
const (
	COSEKeyTypeEC2 = 2 // Elliptic Curve
)

// COSE EC2 curve identifiers
const (
	COSECurveP256 = 1 // P-256 curve
)

// AuthenticatorData flags
const (
	FlagUserPresent      = 0x01 // UP
	FlagUserVerified     = 0x04 // UV
	FlagAttestedCredData = 0x40 // AT
	FlagExtensionData    = 0x80 // ED
)

// Public key credential type
const (
	CredentialTypePublicKey = "public-key"
)
