package database

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func settings() map[string]string {
	return map[string]string{"APP_ENV": "development", "DB_HOST": "127.0.0.1", "DB_PORT": "5432",
		"DB_NAME": "test_db", "DB_USER": "test_user", "DB_PASSWORD": "private:p@ss/'? sslmode=disable", "DB_SSLMODE": "disable"}
}
func lookup(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestPoolConfiguration(t *testing.T) {
	values := settings()
	config, err := Config(lookup(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.Password != values["DB_PASSWORD"] || config.ConnConfig.Database != "test_db" {
		t.Fatal("credentials corrupted by URL encoding")
	}
	if config.MaxConns != 10 || config.MinConns != 0 || config.ConnConfig.ConnectTimeout != 5*time.Second ||
		config.MaxConnLifetime != 30*time.Minute || config.MaxConnIdleTime != 5*time.Minute {
		t.Fatal("pool limits not configured")
	}
	if config.ConnConfig.RuntimeParams["statement_timeout"] != "5000" {
		t.Fatal("missing statement timeout")
	}
}

func TestInvalidDatabaseConfiguration(t *testing.T) {
	for _, change := range []func(map[string]string){
		func(v map[string]string) { delete(v, "DB_PASSWORD") },
		func(v map[string]string) { v["DB_PORT"] = "0" },
		func(v map[string]string) { v["DB_PORT"] = "65536" },
		func(v map[string]string) { v["DB_HOST"] = "remote.example.invalid" },
		func(v map[string]string) { v["APP_ENV"] = "TEST" },
		func(v map[string]string) { v["APP_ENV"] = "PRD" },
		func(v map[string]string) { v["DB_SSLMODE"] = "require" },
		func(v map[string]string) { v["DB_SSLMODE"] = "verify-ca" },
		func(v map[string]string) { v["DB_MAX_CONNS"] = "0" },
		func(v map[string]string) { v["DB_MAX_CONNS"] = "101" },
		func(v map[string]string) {
			v["DB_SSLMODE"] = "verify-full"
			v["DB_SSLROOTCERT"] = "/nonexistent/ca.pem"
		},
		func(v map[string]string) { v["DB_SSLMODE"] = "verify-full"; v["APP_ENV"] = "production" },
	} {
		values := settings()
		change(values)
		if _, err := Config(lookup(values)); err == nil {
			t.Fatal("unsafe or invalid DB configuration accepted")
		} else if strings.Contains(err.Error(), "private:") {
			t.Fatal("credentials exposed")
		}
	}
}

func TestProductionTLSVerifiesServer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, environment := range []string{"TEST", "PRD", "production"} {
		values := settings()
		values["APP_ENV"] = environment
		values["DB_SSLMODE"] = "verify-full"
		values["DB_SSLROOTCERT"] = path
		values["DB_HOST"] = "db.example.invalid"
		config, err := Config(lookup(values))
		if err != nil {
			t.Fatal(err)
		}
		tls := config.ConnConfig.TLSConfig
		if tls == nil || tls.InsecureSkipVerify || tls.ServerName != "db.example.invalid" || tls.RootCAs == nil {
			t.Fatal("server identity not verified")
		}
		for _, fallback := range config.ConnConfig.Fallbacks {
			if fallback.TLSConfig == nil {
				t.Fatal("plaintext fallback enabled")
			}
		}
	}
}

func TestDatabaseUnavailableFailsStartupSafely(t *testing.T) {
	values := settings()
	values["DB_PORT"] = "1"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pool, err := Open(ctx, lookup(values))
	if err == nil {
		pool.Close()
		t.Fatal("unavailable database accepted")
	}
	if strings.Contains(err.Error(), "private:") || strings.Contains(err.Error(), "postgres://") {
		t.Fatal("database startup leaked credentials")
	}
}
