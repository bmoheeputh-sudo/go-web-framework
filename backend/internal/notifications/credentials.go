package notifications

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var ErrCredential = errors.New("notification_credential_unavailable")

// FileCredentials uses a pre-provisioned private shared directory and independent
// notification key. No directories/keys are created by application startup.
// A production secret-manager implementation can replace this interface.
type FileCredentials struct{ directory, keyFile string }

func (*FileCredentials) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[NOTIFICATION SECRET STORE]")
}
func NewFileCredentials(directory, keyFile string) (*FileCredentials, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(keyFile) {
		return nil, ErrCredential
	}
	return &FileCredentials{directory, keyFile}, nil
}
func (s *FileCredentials) open() (*os.Root, []byte, error) {
	d, err := os.Lstat(s.directory)
	if err != nil || !d.IsDir() || d.Mode().Perm()&0077 != 0 {
		return nil, nil, ErrCredential
	}
	info, err := os.Lstat(s.keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
		return nil, nil, ErrCredential
	}
	f, err := os.Open(s.keyFile)
	if err != nil {
		return nil, nil, ErrCredential
	}
	raw, err := io.ReadAll(io.LimitReader(f, 129))
	_ = f.Close()
	if err != nil {
		return nil, nil, ErrCredential
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 || hmac.Equal(key, make([]byte, 32)) {
		return nil, nil, ErrCredential
	}
	root, err := os.OpenRoot(s.directory)
	if err != nil {
		return nil, nil, ErrCredential
	}
	return root, key, nil
}
func (s *FileCredentials) Proof(ctx context.Context, purpose string) (string, error) {
	if ctx.Err() != nil || len(purpose) > 512 {
		return "", ErrCredential
	}
	root, key, err := s.open()
	if err != nil {
		return "", err
	}
	defer root.Close()
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, "vgca.notification.oauth.pkce.v1|"+purpose)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func credentialAAD(b CredentialBinding) ([]byte, string, error) {
	if b.Deployment == "" || b.Environment == "" || b.ConnectorID == "" || b.Version == "" || !mailbox(b.Sender) {
		return nil, "", ErrCredential
	}
	aad, _ := json.Marshal(struct {
		Purpose string
		Binding CredentialBinding
	}{"vgca.notification.gmail.credential.v1", b})
	digest := sha256.Sum256(aad)
	return aad, hex.EncodeToString(digest[:]), nil
}
func lockCredential(ctx context.Context, root *os.Root, name string) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	f, err := root.OpenFile(name+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrCredential
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = f.Close()
			return nil, ErrCredential
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ErrCredential
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func unlockCredential(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }

type credentialWire GmailCredential

func writeCredential(root *os.Root, name string, aad, key []byte, c GmailCredential) error {
	if c.RefreshToken == "" || len(c.RefreshToken) > 8192 || !mailbox(c.Mailbox) || len(c.Scopes) > 1024 {
		return ErrCredential
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ErrCredential
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ErrCredential
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return ErrCredential
	}
	plain, err := json.Marshal(credentialWire(c))
	if err != nil {
		return ErrCredential
	}
	encrypted := aead.Seal(nonce, nonce, plain, aad)
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return ErrCredential
	}
	temp := name + "." + hex.EncodeToString(random) + ".tmp"
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrCredential
	}
	defer root.Remove(temp)
	_, err = f.Write(encrypted)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrCredential
	}
	if root.Rename(temp, name+".enc") != nil {
		return ErrCredential
	}
	dir, err := root.Open(".")
	if err != nil {
		return ErrCredential
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrCredential
	}
	return nil
}
func (s *FileCredentials) Save(ctx context.Context, b CredentialBinding, c GmailCredential) error {
	aad, name, err := credentialAAD(b)
	if err != nil {
		return err
	}
	root, key, err := s.open()
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := lockCredential(ctx, root, name)
	if err != nil {
		return err
	}
	defer unlockCredential(f)
	// Authorization versions are immutable: uncertain finalization never overwrites
	// credentials that another completed flow is using.
	if _, err = root.Lstat(name + ".enc"); !errors.Is(err, os.ErrNotExist) {
		return ErrCredential
	}
	return writeCredential(root, name, aad, key, c)
}
func (s *FileCredentials) Update(ctx context.Context, b CredentialBinding, fn func(GmailCredential) (GmailCredential, Readiness)) (Readiness, error) {
	aad, name, err := credentialAAD(b)
	if err != nil {
		return Readiness{}, err
	}
	root, key, err := s.open()
	if err != nil {
		return Readiness{}, err
	}
	defer root.Close()
	lock, err := lockCredential(ctx, root, name)
	if err != nil {
		return Readiness{}, err
	}
	defer unlockCredential(lock)
	info, err := root.Lstat(name + ".enc")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return Readiness{}, ErrCredential
	}
	f, err := root.Open(name + ".enc")
	if err != nil {
		return Readiness{}, ErrCredential
	}
	encrypted, err := io.ReadAll(io.LimitReader(f, 16385))
	_ = f.Close()
	if err != nil || len(encrypted) > 16384 {
		return Readiness{}, ErrCredential
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	if len(encrypted) < aead.NonceSize()+aead.Overhead() {
		return Readiness{}, ErrCredential
	}
	plain, err := aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], aad)
	if err != nil {
		return Readiness{}, ErrCredential
	}
	var wire credentialWire
	if json.Unmarshal(plain, &wire) != nil {
		return Readiness{}, ErrCredential
	}
	next, result := fn(GmailCredential(wire))
	if !result.Valid() {
		return Readiness{}, ErrCredential
	}
	if err = writeCredential(root, name, aad, key, next); err != nil {
		return Readiness{}, err
	}
	return result, nil
}
