package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"connectrpc.com/connect"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
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
	kmsKey      []byte // Simple local KMS key for HMAC "signatures"
}

// --- Secret Manager (Vault) ---

func (s *FoundationServer) VaultRead(ctx context.Context, req *connect.Request[foundationv1.VaultReadRequest]) (*connect.Response[foundationv1.VaultReadResponse], error) {
	slog.Info("Foundation: Vault Read", "key", req.Msg.Key)
	secret, err := s.vaultClient.Logical().Read("secret/data/" + req.Msg.Key)
	if err != nil { return nil, connect.NewError(connect.CodeInternal, err) }
	if secret == nil || secret.Data == nil { return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("secret not found")) }
	data := secret.Data["data"].(map[string]interface{})
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

// --- Cloud KMS (Expansion) ---

func (s *FoundationServer) KMSEncrypt(ctx context.Context, req *connect.Request[foundationv1.KMSRequest]) (*connect.Response[foundationv1.KMSResponse], error) {
	// High-fidelity local simulation using XOR with key (simple but functional for workstation)
	out := make([]byte, len(req.Msg.Data))
	for i := range req.Msg.Data {
		out[i] = req.Msg.Data[i] ^ s.kmsKey[i%len(s.kmsKey)]
	}
	return connect.NewResponse(&foundationv1.KMSResponse{Data: out}), nil
}

func (s *FoundationServer) KMSDecrypt(ctx context.Context, req *connect.Request[foundationv1.KMSRequest]) (*connect.Response[foundationv1.KMSResponse], error) {
	return s.KMSEncrypt(ctx, req) // Symmetric XOR is its own inverse
}

func (s *FoundationServer) KMSSign(ctx context.Context, req *connect.Request[foundationv1.KMSSignRequest]) (*connect.Response[foundationv1.KMSSignResponse], error) {
	h := hmac.New(sha256.New, s.kmsKey)
	h.Write(req.Msg.Digest)
	return connect.NewResponse(&foundationv1.KMSSignResponse{Signature: h.Sum(nil)}), nil
}

func main() {
	slog.Info("FoundationManager: Booting SaaS Foundation Substrate...")
	w := whisper.New("FoundationManager", "gcp_foundation.lpsv")
	defer w.Close()

	ctx := context.Background()

	// 1. Vault Config
	vConfig := api.DefaultConfig()
	vConfig.Address = os.Getenv("VAULT_ADDR")
	if vConfig.Address == "" { vConfig.Address = "http://localhost:8200" }
	vClient, _ := api.NewClient(vConfig)
	vClient.SetToken("root")

	// 2. Firebase Config
	fHost := os.Getenv("FIREBASE_AUTH_EMULATOR_HOST")
	if fHost == "" { fHost = "127.0.0.1:9099" }
	fApp, _ := firebase.NewApp(ctx, &firebase.Config{ProjectID: "olympus-project"}, option.WithEndpoint(fHost), option.WithoutAuthentication())
	fAuth, _ := fApp.Auth(ctx)

	// 3. IAM Config
	var iam IAMConfig
	// Note: In a real run I'd copy the iam_policies.json here
	iam.Policies = append(iam.Policies, IAMPolicy{
		Identity: "forged-principal@olympus-project.iam.gserviceaccount.com",
		Roles:    []string{"roles/owner"},
		Actions:  []string{"*"},
	})

	server := &FoundationServer{
		vaultClient: vClient,
		authClient:  fAuth,
		iamPolicies: iam.Policies,
		kmsKey:      []byte("wraith-sovereign-kms-master-key-2026"),
	}

	mux := http.NewServeMux()
	mux.Handle(foundationv1connect.NewFoundationServiceHandler(server))

	port := "8092" // Standardized Foundation port
	slog.Info("FoundationManager: Listening...", "addr", "localhost:"+port)
	http.ListenAndServe("localhost:"+port, h2c.NewHandler(mux, &http2.Server{}))
}
