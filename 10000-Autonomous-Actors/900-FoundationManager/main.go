package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/api/option"

	whisper "Olympus2/90000-Enablement-Labs/P0000-pkg/000-whisper"
	foundationv1 "OlympusGCP-Foundation/40000-Communication-Contracts/430-Protocol-Definitions/000-gen/foundation/v1"
	"OlympusGCP-Foundation/40000-Communication-Contracts/430-Protocol-Definitions/000-gen/foundation/v1/foundationv1connect"
)

type IAMPolicy struct {
	Identity string   `json:"identity"`
	Roles    []string `json:"roles"`
	Actions  []string `json:"actions"`
}

type IAMConfig struct {
	Policies []IAMPolicy `json:"policies"`
}

type FoundationServer struct {
	vaultClient *api.Client
	authClient  *auth.Client
	iamPolicies []IAMPolicy
	kmsKey      []byte // Master symmetric key for AES-GCM
	signingKey  []byte // Key for HMAC signatures and JWT minting
}

// --- Secret Manager (Vault) ---

func (s *FoundationServer) VaultRead(ctx context.Context, req *connect.Request[foundationv1.VaultReadRequest]) (*connect.Response[foundationv1.VaultReadResponse], error) {
	slog.Info("Foundation: Vault Read", "key", req.Msg.Key)
	secret, err := s.vaultClient.Logical().Read("secret/data/" + req.Msg.Key)
	if err != nil { return nil, connect.NewError(connect.CodeInternal, err) }
	if secret == nil || secret.Data == nil { return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("secret not found")) }
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok { return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("invalid secret data format")) }
	val, _ := data["value"].(string)
	return connect.NewResponse(&foundationv1.VaultReadResponse{Value: val, Version: 1}), nil
}

func (s *FoundationServer) VaultWrite(ctx context.Context, req *connect.Request[foundationv1.VaultWriteRequest]) (*connect.Response[foundationv1.VaultWriteResponse], error) {
	slog.Info("Foundation: Vault Write", "key", req.Msg.Key)
	data := map[string]interface{}{"data": map[string]interface{}{"value": req.Msg.Value}}
	_, err := s.vaultClient.Logical().Write("secret/data/"+req.Msg.Key, data)
	if err != nil { return nil, connect.NewError(connect.CodeInternal, err) }
	return connect.NewResponse(&foundationv1.VaultWriteResponse{Message: "Secret created", Version: 1}), nil
}

// --- Identity Platform (Firebase Auth) ---

func (s *FoundationServer) CreateUser(ctx context.Context, req *connect.Request[foundationv1.CreateUserRequest]) (*connect.Response[foundationv1.CreateUserResponse], error) {
	params := (&auth.UserToCreate{}).Email(req.Msg.Email).Password(req.Msg.Password)
	u, err := s.authClient.CreateUser(ctx, params)
	if err != nil { return nil, connect.NewError(connect.CodeInternal, err) }
	slog.Info("Foundation: User Created", "uid", u.UID)
	return connect.NewResponse(&foundationv1.CreateUserResponse{Uid: u.UID}), nil
}

func (s *FoundationServer) VerifyToken(ctx context.Context, req *connect.Request[foundationv1.VerifyTokenRequest]) (*connect.Response[foundationv1.VerifyTokenResponse], error) {
	token, err := s.authClient.VerifyIDToken(ctx, req.Msg.IdToken)
	if err != nil { return connect.NewResponse(&foundationv1.VerifyTokenResponse{Valid: false}), nil }
	return connect.NewResponse(&foundationv1.VerifyTokenResponse{Uid: token.UID, Valid: true}), nil
}

// --- Cloud IAM ---

func (s *FoundationServer) LookupIdentity(ctx context.Context, req *connect.Request[foundationv1.LookupIdentityRequest]) (*connect.Response[foundationv1.LookupIdentityResponse], error) {
	for _, p := range s.iamPolicies {
		if strings.Contains(req.Msg.Token, p.Identity) {
			return connect.NewResponse(&foundationv1.LookupIdentityResponse{
				ServiceAccount: p.Identity,
				ProjectId:      "olympus-project",
				Roles:          p.Roles,
			}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("identity not found"))
}

func (s *FoundationServer) TestIAMPolicy(ctx context.Context, req *connect.Request[foundationv1.TestIAMPolicyRequest]) (*connect.Response[foundationv1.TestIAMPolicyResponse], error) {
	slog.Info("Foundation: Evaluating IAM Policy", "identity", req.Msg.Identity, "action", req.Msg.Action)
	allowed := false
	reason := "Denied by local IAM engine"
	for _, p := range s.iamPolicies {
		if p.Identity == req.Msg.Identity {
			for _, a := range p.Actions {
				if a == req.Msg.Action || a == "*" {
					allowed = true
					reason = "Allowed by local policy entry"
					break
				}
			}
		}
	}
	return connect.NewResponse(&foundationv1.TestIAMPolicyResponse{Allowed: allowed, Reason: reason}), nil
}

// --- Cloud KMS (Production-Grade Deepening) ---

func (s *FoundationServer) KMSEncrypt(ctx context.Context, req *connect.Request[foundationv1.KMSRequest]) (*connect.Response[foundationv1.KMSResponse], error) {
	block, _ := aes.NewCipher(s.kmsKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, req.Msg.Data, nil)
	return connect.NewResponse(&foundationv1.KMSResponse{Data: ciphertext}), nil
}

func (s *FoundationServer) KMSDecrypt(ctx context.Context, req *connect.Request[foundationv1.KMSRequest]) (*connect.Response[foundationv1.KMSResponse], error) {
	block, _ := aes.NewCipher(s.kmsKey)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := req.Msg.Data[:nonceSize], req.Msg.Data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil { return nil, connect.NewError(connect.CodeInvalidArgument, err) }
	return connect.NewResponse(&foundationv1.KMSResponse{Data: plaintext}), nil
}

func (s *FoundationServer) KMSSign(ctx context.Context, req *connect.Request[foundationv1.KMSSignRequest]) (*connect.Response[foundationv1.KMSSignResponse], error) {
	h := hmac.New(sha256.New, s.signingKey)
	h.Write(req.Msg.Digest)
	return connect.NewResponse(&foundationv1.KMSSignResponse{Signature: h.Sum(nil)}), nil
}

// --- Database Auth (Deepening) ---

func (s *FoundationServer) MintDatabaseToken(ctx context.Context, req *connect.Request[foundationv1.DBTokenRequest]) (*connect.Response[foundationv1.DBTokenResponse], error) {
	slog.Info("Foundation: Minting Database Auth Token", "identity", req.Msg.Identity, "instance", req.Msg.InstanceId)
	
	// Create high-fidelity local JWT for IAM DB Auth emulation
	claims := jwt.MapClaims{
		"sub": req.Msg.Identity,
		"iss": "olympus-foundation-minter",
		"aud": req.Msg.InstanceId,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(s.signingKey)
	if err != nil { return nil, connect.NewError(connect.CodeInternal, err) }

	return connect.NewResponse(&foundationv1.DBTokenResponse{
		AccessToken: ss,
		ExpiresIn:   3600,
	}), nil
}

func main() {
	slog.Info("FoundationManager: Booting SaaS Foundation Substrate (Phase 7)...")
	w := whisper.New("FoundationManager", "gcp_foundation.lpsv")
	defer w.Close()

	ctx := context.Background()

	// 1. Vault Config
	vConfig := api.DefaultConfig()
	vConfig.Address = os.Getenv("VAULT_ADDR")
	if vConfig.Address == "" { vConfig.Address = "http://localhost:8200" }
	vClient, err := api.NewClient(vConfig)
	if err != nil { slog.Error("Failed to create vault client", "error", err); os.Exit(1) }
	vClient.SetToken("root")

	// 2. Firebase Config
	fHost := os.Getenv("FIREBASE_AUTH_EMULATOR_HOST")
	if fHost == "" { fHost = "127.0.0.1:9099" }
	fApp, err := firebase.NewApp(ctx, &firebase.Config{ProjectID: "olympus-project"}, option.WithEndpoint(fHost), option.WithoutAuthentication())
	if err != nil { slog.Error("Failed to create firebase app", "error", err); os.Exit(1) }
	fAuth, err := fApp.Auth(ctx)
	if err != nil { slog.Error("Failed to create auth client", "error", err); os.Exit(1) }

	var iam IAMConfig
	data, err := os.ReadFile("C0100-Configuration-Registry/settings/iam_policies.json")
	if err == nil { json.Unmarshal(data, &iam) }

	server := &FoundationServer{
		vaultClient: vClient,
		authClient:  fAuth,
		iamPolicies: iam.Policies,
		kmsKey:      []byte("12345678901234567890123456789012"), // 32 bytes for AES-256
		signingKey:  []byte("wraith-sovereign-master-signing-key"),
	}

	mux := http.NewServeMux()
	mux.Handle(foundationv1connect.NewFoundationServiceHandler(server))

	addr := "localhost:8092"
	slog.Info("FoundationManager: Listening...", "addr", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      h2c.NewHandler(mux, &http2.Server{}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
