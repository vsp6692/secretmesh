// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package notify

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"testing"

	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func TestMessageHeaders(t *testing.T) {
	from, _ := mail.ParseAddress("SecretMesh <sm@example.com>")
	to, _ := mail.ParseAddress("a@example.com")
	msg := string(message(from, to, "Rotation due: x\r\nBcc: victim@example.com", "body line\nsecond"))
	head, body, _ := strings.Cut(msg, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("header injected: %q", line)
		}
	}
	if !strings.Contains(head, "Subject: Rotation due: x Bcc: victim@example.com") || !strings.Contains(body, "second") {
		t.Fatalf("message:\n%s", msg)
	}
}

func TestSlackOnlyPostsToAllowedWebhooks(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	s := &Slack{Prefixes: []string{redirect.URL + "/services/"}}
	ctx := context.Background()

	if err := s.Send(ctx, sensitive.FromString(target.URL+"/services/x"), "hi"); err == nil || hits != 0 {
		t.Fatalf("posted to a host outside the allow-list: %v", err)
	}
	if err := s.Send(ctx, sensitive.FromString(redirect.URL+"/other"), "hi"); err == nil {
		t.Fatal("posted outside the allowed path")
	}
	err := s.Send(ctx, sensitive.FromString(redirect.URL+"/services/T/B/secret-token"), "hi")
	if err == nil || hits != 0 {
		t.Fatalf("followed a redirect: %v (hits %d)", err, hits)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("error contains the webhook URL")
	}
}

func TestSMTPRequiresStartTLS(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = io.WriteString(c, "220 plain\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(strings.ToUpper(line), "EHLO") {
				_, _ = io.WriteString(c, "250 plain\r\n") // no STARTTLS offered
				continue
			}
			_, _ = io.WriteString(c, "250 ok\r\n")
		}
	}()
	s := &SMTP{Addr: l.Addr().String(), From: "sm@example.com", TLS: "starttls", Username: "u", Password: sensitive.FromString("p")}
	if err := s.Send(context.Background(), "a@example.com", "s", "b"); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("sent without TLS: %v", err)
	}
}
