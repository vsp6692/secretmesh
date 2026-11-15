// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package httpapi_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mailSink is a minimal SMTP server that records messages.
type mailSink struct {
	addr string
	mu   sync.Mutex
	msgs []mailMsg
}

type mailMsg struct{ To, Data string }

func newMailSink(t *testing.T) *mailSink {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	m := &mailSink{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m
}

func (m *mailSink) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	reply := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	reply("220 sink")
	var to []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			reply("250 sink")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			to = append(to, strings.Trim(strings.TrimSpace(line)[8:], "<> "))
			reply("250 ok")
		case strings.HasPrefix(cmd, "DATA"):
			reply("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			m.mu.Lock()
			for _, rcpt := range to {
				m.msgs = append(m.msgs, mailMsg{To: rcpt, Data: b.String()})
			}
			m.mu.Unlock()
			to = nil
			reply("250 queued")
		case strings.HasPrefix(cmd, "QUIT"):
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func (m *mailSink) messages() []mailMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailMsg(nil), m.msgs...)
}

// slackSink stands in for a Slack incoming webhook.
type slackSink struct {
	*httptest.Server
	mu       sync.Mutex
	posts    []string
	failNext int // HTTP status to return once
}

func newSlackSink(t *testing.T) *slackSink {
	s := &slackSink{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.failNext != 0 {
			w.WriteHeader(s.failNext)
			s.failNext = 0
			return
		}
		s.posts = append(s.posts, r.URL.Path+" "+string(b))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *slackSink) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.posts...)
}

func (s *slackSink) failOnce(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = status
}
