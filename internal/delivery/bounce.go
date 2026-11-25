package delivery

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/DevHatRo/outbound-smtp/internal/store"
)

// Failure is one recipient that will never be delivered.
type Failure struct {
	Address  string
	Response string // remote reply or local reason
	Host     string // remote server, may be ""
}

var enhancedCode = regexp.MustCompile(`\b([245]\.\d{1,3}\.\d{1,3})\b`)

// statusOf extracts the enhanced status code from a reply, or a generic one.
func statusOf(response string) string {
	if m := enhancedCode.FindString(response); m != "" && m[0] != '2' {
		return m
	}
	return "5.0.0"
}

const maxReturnedHeaders = 32 << 10

// BuildDSN builds an RFC 3464 delivery status notification for the failed
// recipients of orig. It returns the unsigned message addressed to the
// original envelope sender; the caller signs and queues it with a null
// envelope sender so it can never bounce back in a loop.
func BuildDSN(hostname string, orig store.Message, failures []Failure, now time.Time) []byte {
	date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
	boundary := "dsn-" + store.NewID()
	var b bytes.Buffer
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\r\n", a...) }

	// postmaster of the original sending domain: a domain we hold a DKIM key
	// for, so the bounce is signed and aligned like any other message.
	w("From: Mail Delivery System <postmaster@%s>", orig.FromDomain)
	w("To: <%s>", orig.EnvelopeFrom)
	w("Subject: Undelivered Mail Returned to Sender")
	w("Date: %s", date)
	w("Message-ID: <%s@%s>", strings.ToLower(store.NewID()), hostname)
	w("Auto-Submitted: auto-replied")
	w("MIME-Version: 1.0")
	w(`Content-Type: multipart/report; report-type=delivery-status; boundary="%s"`, boundary)
	w("")
	w("This is a MIME-encapsulated message.")
	w("")

	w("--%s", boundary)
	w("Content-Type: text/plain; charset=utf-8")
	w("Content-Transfer-Encoding: 8bit")
	w("")
	w("This is the mail system at %s.", hostname)
	w("")
	w("Your message could not be delivered to one or more recipients.")
	w("It will not be retried.")
	w("")
	for _, f := range failures {
		w("<%s>: %s", f.Address, f.Response)
	}
	w("")

	w("--%s", boundary)
	w("Content-Type: message/delivery-status")
	w("")
	w("Reporting-MTA: dns; %s", hostname)
	w("X-Queue-ID: %s", orig.ID)
	w("Arrival-Date: %s", time.Unix(orig.CreatedAt, 0).UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	for _, f := range failures {
		w("")
		w("Final-Recipient: rfc822; %s", f.Address)
		w("Action: failed")
		w("Status: %s", statusOf(f.Response))
		if f.Host != "" {
			w("Remote-MTA: dns; %s", f.Host)
		}
		w("Diagnostic-Code: smtp; %s", f.Response)
	}
	w("")

	// Headers only: enough to identify the message without sending the
	// content back to a possibly forged sender.
	headers, _, _ := bytes.Cut(orig.Body, []byte("\r\n\r\n"))
	if len(headers) > maxReturnedHeaders {
		headers = headers[:maxReturnedHeaders]
		if i := bytes.LastIndex(headers, []byte("\r\n")); i >= 0 { // end on a whole line
			headers = headers[:i]
		}
	}
	w("--%s", boundary)
	w("Content-Type: text/rfc822-headers")
	w("")
	b.Write(headers)
	w("")
	w("")
	w("--%s--", boundary)
	return b.Bytes()
}
