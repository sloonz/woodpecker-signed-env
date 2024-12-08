package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-ap/httpsig"
	"github.com/golang-jwt/jwt/v5"
	"go.woodpecker-ci.org/woodpecker/v2/server/model"
	"gopkg.in/yaml.v3"
)

const woodpeckerPubKeyID = "woodpecker-ci-plugins"

type config struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type incoming struct {
	Repo          *model.Repo     `json:"repo"`
	Build         *model.Pipeline `json:"pipeline"`
	Configuration []*config       `json:"configs",omitempty`
}

type repoPayload struct {
	jwt.RegisteredClaims
	*model.Repo
}

type buildPayload struct {
	jwt.RegisteredClaims
	*model.Pipeline
}

func injectEnvironment(data string, env map[string]string) (string, error) {
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(data), &config); err != nil {
		return "", err
	}

	stepsInterface, exists := config["steps"]
	if !exists {
		return data, nil
	}

	steps, ok := stepsInterface.([]interface{})
	if !ok {
		return data, nil
	}

	for i := range steps {
		step, ok := steps[i].(map[string]interface{})
		if !ok {
			continue
		}

		var stepEnv map[string]interface{}
		if envInterface, exists := step["environment"]; exists {
			stepEnv, ok = envInterface.(map[string]interface{})
			if !ok {
				stepEnv = make(map[string]interface{})
			}
		} else {
			stepEnv = make(map[string]interface{})
		}

		for key, value := range env {
			stepEnv[key] = value
		}

		step["environment"] = stepEnv
		steps[i] = step
	}

	output, err := yaml.Marshal(&config)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func main() {
	privKey, err := jwt.ParseEdPrivateKeyFromPEM([]byte(os.Getenv("JWT_PRIVATE_KEY")))
	if err != nil {
		panic(err)
	}

	var verifier *httpsig.Verifier
	noVerify := os.Getenv("WOODPECKER_SIGNATURE_NOVERIFY") == "1"
	if !noVerify {
		pemBlock, _ := pem.Decode([]byte(os.Getenv("WOODPECKER_SIGNATURE_PUBLIC_KEY")))
		if pemBlock == nil {
			log.Fatalf("Failed to parse public key file")
		}

		b, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			log.Fatal("Failed to parse public key file ", err)
		}

		pubKey, ok := b.(ed25519.PublicKey)
		if !ok {
			log.Fatal("Failed to parse public key file")
		}

		keystore := httpsig.NewMemoryKeyStore()
		keystore.SetKey(woodpeckerPubKeyID, pubKey)

		verifier = httpsig.NewVerifier(keystore)
		verifier.SetRequiredHeaders([]string{"(request-target)", "date"})
	}

	expirationTime := time.Duration(15)
	if envExpiration := os.Getenv("JWT_EXPIRATION_TIME"); envExpiration != "" {
		parsed, err := strconv.Atoi(envExpiration)
		if err == nil && parsed > 0 {
			expirationTime = time.Duration(parsed)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ciconfig", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if !noVerify {
			keyID, err := verifier.Verify(r)
			if err != nil {
				log.Printf("config: invalid or missing signature in http.Request")
				http.Error(w, "Invalid or Missing Signature", http.StatusBadRequest)
				return
			}

			if keyID != woodpeckerPubKeyID {
				log.Printf("config: invalid signature in http.Request")
				http.Error(w, "Invalid Signature", http.StatusBadRequest)
				return
			}
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var input incoming
		if err := json.Unmarshal(body, &input); err != nil {
			http.Error(w, fmt.Sprintf("Error parsing JSON: %v", err), http.StatusBadRequest)
			return
		}

		now := time.Now()

		repo := repoPayload{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(expirationTime * time.Minute)),
			},
			Repo: input.Repo,
		}

		build := buildPayload{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(expirationTime * time.Minute)),
			},
			Pipeline: input.Build,
		}

		signedRepo, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, repo).SignedString(privKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error signing repo data: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		signedBuild, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, build).SignedString(privKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error signing build data: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		env := map[string]string{
			"CI_SIGNED_REPO":  signedRepo,
			"CI_SIGNED_BUILD": signedBuild,
		}

		var modifiedConfigs []*config
		for _, cfg := range input.Configuration {
			if cfg == nil {
				continue
			}

			newData, err := injectEnvironment(cfg.Data, env)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error processing configuration %s: %v", cfg.Name, err), http.StatusInternalServerError)
				return
			}

			modifiedConfigs = append(modifiedConfigs, &config{
				Name: cfg.Name,
				Data: newData,
			})
		}

		input.Configuration = modifiedConfigs

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(input); err != nil {
			http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	err = http.ListenAndServe(os.Getenv("LISTEN_ADDR"), mux)
	if err != nil {
		log.Fatalf("Error on listen: %v", err)
	}
}
