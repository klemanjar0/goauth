package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time      = 3         // Number of iterations
	argon2Memory    = 64 * 1024 // Memory in KiB (64 MB)
	argon2Threads   = 4         // Parallelism factor
	argon2KeyLength = 32        // Length of the derived key in bytes
	saltLength      = 16        // Length of the salt in bytes
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrPasswordTooLong     = errors.New("password exceeds maximum length")
	ErrPasswordEmpty       = errors.New("password cannot be empty")
)

const maxPasswordLength = 172 // Common reasonable limit

type PasswordHasher struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		time:    argon2Time,
		memory:  argon2Memory,
		threads: argon2Threads,
		keyLen:  argon2KeyLength,
	}
}

// HashPassword generates a secure hash of the password using Argon2id
func (p *PasswordHasher) HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrPasswordEmpty
	}

	if len(password) > maxPasswordLength {
		return "", ErrPasswordTooLong
	}

	salt, err := generateSalt(saltLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, p.keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.memory,
		p.time,
		p.threads,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

func (p *PasswordHasher) VerifyPassword(password, encodedHash string) (bool, error) {
	if password == "" {
		return false, ErrPasswordEmpty
	}

	if len(password) > maxPasswordLength {
		return false, ErrPasswordTooLong
	}

	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, params.keyLen)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}

	return false, nil
}

type hashParams struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func decodeHash(encodedHash string) (*hashParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params := &hashParams{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.keyLen = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.keyLen = uint32(len(hash))

	return params, salt, hash, nil
}

func generateSalt(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// __global__
var defaultHasher = NewPasswordHasher()

func HashPassword(password string) (string, error) {
	return defaultHasher.HashPassword(password)
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	return defaultHasher.VerifyPassword(password, encodedHash)
}
