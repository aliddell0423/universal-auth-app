package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/verify"
)

const (
	StatusApproved      = "approved"
	StatusDenied        = "denied"
	StatusTimeout       = "timeout"
	StatusSecurityError = "security_error"
)

type Request struct {
	Source   string
	Kind     string
	Resource string
	Message  string
}

type Result struct {
	Status string
}

type Service struct {
	Client *broker.Client
	Config *config.Config
}

func (s *Service) Authenticate(ctx context.Context, req Request, poll time.Duration) (Result, error) {
	clientNonce, err := generateClientNonce()
	if err != nil {
		return Result{}, err
	}

	createReq := broker.CreateRequest{
		Source:      req.Source,
		Kind:        req.Kind,
		Resource:    req.Resource,
		Message:     req.Message,
		ClientNonce: clientNonce,
	}

	pending, err := s.Client.CreateRequest(ctx, createReq, "")
	if err != nil {
		return Result{}, err
	}

	if err := s.Client.ValidatePendingResponse(pending, createReq); err != nil {
		return Result{Status: StatusSecurityError}, err
	}

	intent := verify.PendingIntent{
		RequestID:   pending.ID,
		Challenge:   pending.Challenge,
		ClientNonce: clientNonce,
		Source:      req.Source,
		Kind:        req.Kind,
		Resource:    req.Resource,
		Message:     req.Message,
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return Result{Status: StatusTimeout}, ctx.Err()
		case <-ticker.C:
			result, err := s.Client.GetRequest(ctx, pending.ID, "")
			if err != nil {
				return Result{}, err
			}
			switch result.Status {
			case "approved":
				if err := verify.VerifyApproval(s.Config.TrustedDevice, intent, result); err != nil {
					return Result{Status: StatusSecurityError}, err
				}
				return Result{Status: StatusApproved}, nil
			case "denied":
				return Result{Status: StatusDenied}, nil
			case "pending":
				// continue waiting
			default:
				return Result{}, fmt.Errorf("unexpected request status %q", result.Status)
			}
		}
	}
}

func generateClientNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
