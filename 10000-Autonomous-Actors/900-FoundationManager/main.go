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
	kmsKey      []byte
	signingKey  []byte
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

// --- Cloud KMS ---

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

// --- Database Auth & Workload Identity (Deepening) ---

func (s *FoundationServer) MintDatabaseToken(ctx context.Context, req *connect.Request[foundationv1.DBTokenRequest]) (*connect.Response[foundationv1.DBTokenResponse], error) {
	slog.Info("Foundation: Minting Database Auth Token", "identity", req.Msg.Identity, "instance", req.Msg.InstanceId)
	claims := jwt.MapClaims{
		"sub": req.Msg.Identity,
		"iss": "olympus-foundation-minter",
		"aud": req.Msg.InstanceId,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(s.signingKey)
	if err != nil { return nil, connect.NewError(connect.CodeInternal, err) }
	return connect.NewResponse(&foundationv1.DBTokenResponse{AccessToken: ss, ExpiresIn: 3600}), nil
}

func (s *FoundationServer) ImpersonateServiceAccount(ctx context.Context, req *connect.Request[foundationv1.ImpersonateRequest]) (*connect.Response[foundationv1.DBTokenResponse], error) {
	slog.Info("Foundation: Simulating Workload Identity Impersonation", "instigator", req.Msg.InstigatorIdentity, "target", req.Msg.TargetServiceAccount)
	
	// Deep Logic: Check if instigator has 'iam.serviceAccounts.getAccessToken' on target
	allowed := false
	for _, p := range s.iamPolicies {
		if p.Identity == req.Msg.InstigatorIdentity {
			for _, a := range p.Actions {
				if a == "iam.serviceAccounts.getAccessToken" || a == "*" {
					allowed = true
					break
				}
			}
		}
	}

	if !allowed {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("identity %s not authorized to impersonate %s", req.Msg.InstigatorIdentity, req.Msg.TargetServiceAccount))
	}

	// Mint token for the TARGET account
	claims := jwt.MapClaims{
		"sub": req.Msg.TargetServiceAccount,
		"iss": "olympus-workload-identity-federation",
		"exp": time.Now().Add(time.Hour).Unix(),
		"scopes": req.Msg.Scopes,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ := token.SignedString(s.signingKey)

	return connect.NewResponse(&foundationv1.DBTokenResponse{
		AccessToken: ss,
		ExpiresIn:   3600,
	}), nil
}

func main() {
	slog.Info("FoundationManager: Booting SaaS Foundation Substrate (Phase 9)...")
	w := whisper.New("FoundationManager", "gcp_foundation.lpsv")
	defer w.Close()

	ctx := context.Background()

	vConfig := api.DefaultConfig()
	vConfig.Address = os.Getenv("VAULT_ADDR")
	if vConfig.Address == "" { vConfig.Address = "http://localhost:8200" }
	vClient, _ := api.NewClient(vConfig)
	vClient.SetToken("root")

	fHost := os.Getenv("FIREBASE_AUTH_EMULATOR_HOST")
	if fHost == "" { fHost = "127.0.0.1:9099" }
	fApp, _ := firebase.NewApp(ctx, &firebase.Config{ProjectID: "olympus-project"}, option.WithEndpoint(fHost), option.WithoutAuthentication())
	fAuth, _ := fApp.Auth(ctx)

	var iam IAMConfig
	data, _ := os.ReadFile("C0100-Configuration-Registry/settings/iam_policies.json")
	json.Unmarshal(data, &iam)

	server := &FoundationServer{
		vaultClient: vClient,
		authClient:  fAuth,
		iamPolicies: iam.Policies,
		kmsKey:      []byte("12345678901234567890123456789012"),
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
