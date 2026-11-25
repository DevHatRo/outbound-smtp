package smtpd

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/DevHatRo/outbound-smtp/internal/config"
	"github.com/DevHatRo/outbound-smtp/internal/store"
)

// maxReceived is the hop count above which a message is treated as a loop.
const maxReceived = 50

// errBadMessage wraps problems with the message itself (5xx to the client).
var errBadMessage = errors.New("bad message")

// headerFrom returns the single author address of the message. Messages with
// no From, several From fields or several mailboxes are refused because the
// DKIM signing domain would be ambiguous.
func headerFrom(h mail.Header) (addr, domain string, err error) {
	if n := len(h["From"]); n != 1 {
		return "", "", fmt.Errorf("%w: need exactly one From header field, found %d", errBadMessage, n)
	}
	list, err := mail.ParseAddressList(h.Get("From"))
	if err != nil {
		return "", "", fmt.Errorf("%w: unparsable From header", errBadMessage)
	}
	if len(list) != 1 {
		return "", "", fmt.Errorf("%w: From header must contain exactly one address", errBadMessage)
	}
	_, domain, err = store.SplitAddress(list[0].Address)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid From address", errBadMessage)
	}
	return list[0].Address, domain, nil
}

// prepare validates the message and returns it with Bcc removed, Date and
// Message-ID added when missing, and our Received field prepended.
func prepare(raw []byte, queueID, hostname, with string, now time.Time) (out []byte, fromAddr, fromDomain string, err error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: malformed headers", errBadMessage)
	}
	if len(msg.Header["Received"]) > maxReceived {
		return nil, "", "", fmt.Errorf("%w: too many Received headers (mail loop)", errBadMessage)
	}
	if fromAddr, fromDomain, err = headerFrom(msg.Header); err != nil {
		return nil, "", "", err
	}

	header, body := splitMessage(raw)
	date := now.Format(time.RFC1123Z)
	var b bytes.Buffer
	b.WriteString(config.ReceivedHeader(hostname, with, queueID, now))
	// Blind-copy fields never leave the relay. An empty Date or Message-ID is
	// dropped too, so the generated one is not a second instance.
	drop := map[string]bool{"bcc": true, "resent-bcc": true}
	if msg.Header.Get("Date") == "" {
		fmt.Fprintf(&b, "Date: %s\r\n", date)
		drop["date"] = true
	}
	if msg.Header.Get("Message-Id") == "" {
		fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", strings.ToLower(queueID), hostname)
		drop["message-id"] = true
	}
	for _, field := range header {
		name, _, _ := bytes.Cut(field, []byte(":"))
		if drop[strings.ToLower(string(bytes.TrimSpace(name)))] {
			continue
		}
		b.Write(field)
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes(), fromAddr, fromDomain, nil
}

// splitMessage cuts raw into header fields (each with its folded continuation
// lines and a CRLF line ending) and the body after the blank line.
func splitMessage(raw []byte) (fields [][]byte, body []byte) {
	for len(raw) > 0 {
		line := raw
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			line, raw = raw[:i+1], raw[i+1:]
		} else {
			raw = nil
		}
		// Copy: appending to a sub-slice of raw would overwrite the next line.
		line = append(bytes.Clone(bytes.TrimRight(line, "\r\n")), '\r', '\n')
		if len(line) == 2 { // blank line: end of headers
			return fields, raw
		}
		if (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			fields[len(fields)-1] = append(fields[len(fields)-1], line...)
			continue
		}
		fields = append(fields, line)
	}
	return fields, nil
}
