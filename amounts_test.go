package paymos

import "testing"

func TestParseUnits(t *testing.T) {
	cases := map[string]string{
		"1.5":      "1500000",
		"1":        "1000000",
		"0.000001": "1",
	}
	for human, want := range cases {
		got, err := ParseUnits(human, 6)
		if err != nil {
			t.Fatalf("ParseUnits(%q): %v", human, err)
		}
		if got != want {
			t.Fatalf("ParseUnits(%q) = %q, want %q", human, got, want)
		}
	}
	got, err := ParseUnits("12", 0)
	if err != nil || got != "12" {
		t.Fatalf(`ParseUnits("12", 0) = %q, %v`, got, err)
	}
}

func TestParseUnitsRejects(t *testing.T) {
	for _, bad := range []string{"-1", "abc", "", "1,5", "1.2.3", " ", "1."} {
		if _, err := ParseUnits(bad, 6); err == nil {
			t.Fatalf("ParseUnits(%q) should have failed", bad)
		}
	}
	if _, err := ParseUnits("1.1234567", 6); err == nil {
		t.Fatal("too many fractional digits should fail")
	}
}

func TestSurvivesAmountsADoubleWouldRound(t *testing.T) {
	// 18 decimals: past what an IEEE 754 double holds exactly, which is the reason these are
	// strings.
	raw, err := ParseUnits("123456789.123456789123456789", 18)
	if err != nil {
		t.Fatal(err)
	}
	if raw != "123456789123456789123456789" {
		t.Fatalf("raw = %q", raw)
	}
	back, err := FormatUnits(raw, 18)
	if err != nil || back != "123456789.123456789123456789" {
		t.Fatalf("format = %q, %v", back, err)
	}
}

func TestFormatUnits(t *testing.T) {
	cases := map[string]string{
		"1500000": "1.5",
		"1000000": "1",
		"1":       "0.000001",
	}
	for raw, want := range cases {
		got, err := FormatUnits(raw, 6)
		if err != nil || got != want {
			t.Fatalf("FormatUnits(%q, 6) = %q, %v; want %q", raw, got, err, want)
		}
	}
	got, err := FormatUnits("12", 0)
	if err != nil || got != "12" {
		t.Fatalf(`FormatUnits("12", 0) = %q, %v`, got, err)
	}
}

func TestRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		human string
		dec   int
	}{{"1.5", 6}, {"0.000001", 6}, {"1000", 18}, {"7", 0}} {
		raw, err := ParseUnits(tc.human, tc.dec)
		if err != nil {
			t.Fatal(err)
		}
		back, err := FormatUnits(raw, tc.dec)
		if err != nil || back != tc.human {
			t.Fatalf("round trip of %q = %q, %v", tc.human, back, err)
		}
	}
}
