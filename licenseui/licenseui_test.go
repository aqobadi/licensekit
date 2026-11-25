package licenseui_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/licensekittest"
	"github.com/aqobadi/licensekit/licenseui"
)

func form(h http.Handler, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPage(t *testing.T) {
	iss := licensekittest.New(t, "moro-ai")
	lic := iss.Open(t, licensekit.Options{ServerURL: iss.Server(t)})
	h := licenseui.Handler(lic, licenseui.Options{Name: "Moro AI", Support: "Email help@example.com"})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Not activated") || !strings.Contains(body, "help@example.com") || strings.Contains(body, "<script") {
		t.Fatalf("%d\n%s", w.Code, body)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/licenseui.css", nil))
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Fatal("stylesheet")
	}

	// Activate online with a license key.
	key := iss.NewKey(licensekittest.Terms{Expires: time.Now().AddDate(1, 0, 0)})
	w = form(h, url.Values{"action": {"enter"}, "code": {key}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Activated.") || !strings.Contains(w.Body.String(), "Deactivate this computer") {
		t.Fatalf("%d\n%s", w.Code, w.Body)
	}
	// A typo is reported with its group.
	bad := "0000-0000-0000-0000-0000-0001"
	if w = form(h, url.Values{"action": {"enter"}, "code": {bad}}); w.Code != 422 || !strings.Contains(w.Body.String(), "typo") {
		t.Fatalf("%d\n%s", w.Code, w.Body)
	}
	// A request file downloads.
	if w = form(h, url.Values{"action": {"request"}, "code": {key}}); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "license request.txt") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	// Deactivate.
	if w = form(h, url.Values{"action": {"deactivate"}}); w.Code != 200 || lic.Status().State != licensekit.NotActivated {
		t.Fatalf("%d\n%s", w.Code, w.Body)
	}
	// A cross-site post is refused.
	r := httptest.NewRequest("POST", "/", strings.NewReader("action=deactivate"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", w.Code)
	}
}

func TestLicenseFileUpload(t *testing.T) {
	iss := licensekittest.New(t, "moro-ai")
	lic := iss.Open(t, licensekit.Options{})
	h := licenseui.Handler(lic, licenseui.Options{})
	_, req, _ := lic.RequestFile(iss.NewKey(licensekittest.Terms{}))
	file, _ := iss.LicenseFile(req)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("action", "file")
	fw, _ := mw.CreateFormFile("file", "Moro AI.license")
	fw.Write(file)
	mw.Close()
	r := httptest.NewRequest("POST", "/", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || lic.Status().State != licensekit.Active {
		t.Fatalf("%d\n%s", w.Code, w.Body)
	}
}
