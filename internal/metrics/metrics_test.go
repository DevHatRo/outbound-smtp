package metrics

import (
	"errors"
	"testing"
	"time"
)

func TestQueueGaugesReadTheQueueOncePerScrape(t *testing.T) {
	var calls int
	var fail error
	m := New("test")
	m.RegisterQueue(func() (int64, int64, int64, error) {
		calls++
		return 3, 2, time.Now().Add(-time.Minute).Unix(), fail
	})
	scrape := func() map[string]float64 {
		t.Helper()
		families, err := m.Registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]float64{}
		for _, f := range families {
			for _, metric := range f.GetMetric() {
				name := f.GetName()
				for _, l := range metric.GetLabel() {
					name += ":" + l.GetValue()
				}
				got[name] = metric.GetGauge().GetValue()
			}
		}
		return got
	}

	got := scrape()
	if calls != 1 {
		t.Errorf("queue read %d times in one scrape, want 1", calls)
	}
	if got["smtprelay_queue_depth:pending"] != 3 || got["smtprelay_queue_depth:deferred"] != 2 {
		t.Errorf("depth = %v", got)
	}
	if age := got["smtprelay_queue_oldest_message_age_seconds"]; age < 59 || age > 120 {
		t.Errorf("oldest age = %v, want about 60", age)
	}

	fail = errors.New("database is locked")
	got = scrape()
	if got["smtprelay_queue_depth:pending"] != -1 || got["smtprelay_queue_oldest_message_age_seconds"] != 0 {
		t.Errorf("unreadable queue = %v, want depth -1 and age 0", got)
	}
}
