// Package licenseui is a ready-made License page for web applications that
// use licensekit. Mount it behind your administrator sign-in:
//
//	mux.Handle("/settings/license/", http.StripPrefix("/settings/license", requireAdmin(
//		licenseui.Handler(lic, licenseui.Options{Name: "Moro AI"}))))
//
// The page lets an administrator activate with a license key (online), apply
// a renewal code, open a license file, save a request file when there is no
// internet, and deactivate the computer. It needs no JavaScript, rejects
// cross-origin form posts, and serves its stylesheet from its own path, so
// it works under a strict Content-Security-Policy.
package licenseui

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/online"
)

// Options configure the page. The zero value works.
type Options struct {
	Name    string // product name shown in the heading, e.g. "Moro AI"
	Support string // how customers reach you; default "To get a license key or a renewal code, contact us."
}

//go:embed page.html
var pageHTML string

//go:embed licenseui.css
var css []byte

var page = template.Must(template.New("page").Parse(pageHTML))

// maxUpload bounds a license file or form post.
const maxUpload = 64 << 10

type view struct {
	Name, Support string
	S             licensekit.Status
	Error, Done   string
	Warn          bool
}

// Handler returns the License page for lic.
func Handler(lic *licensekit.License, opts Options) http.Handler {
	if opts.Name == "" {
		opts.Name = "this app"
	}
	if opts.Support == "" {
		opts.Support = "Need a license key or renewal code? Contact us."
	}
	h := &handler{lic: lic, opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /licenseui.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(css)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { h.render(w, http.StatusOK, "", "") })
	mux.HandleFunc("POST /{$}", h.post)
	return http.NewCrossOriginProtection().Handler(mux)
}

type handler struct {
	lic  *licensekit.License
	opts Options
}

func (h *handler) render(w http.ResponseWriter, status int, done, failed string) {
	s := h.lic.Status()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	page.Execute(w, view{Name: h.opts.Name, Support: h.opts.Support, S: s, Done: done, Error: failed,
		Warn: s.State == licensekit.Active && !s.Perpetual && s.DaysLeft <= 30})
}

func (h *handler) post(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+4096)
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var err error
	done := ""
	switch r.FormValue("action") {
	case "enter":
		before := h.lic.Status()
		if err = online.Enter(ctx, h.lic, r.FormValue("code")); err == nil {
			done = "Done. " + h.lic.Status().Message
			if before.State == licensekit.NotActivated {
				done = "Activated. " + h.lic.Status().Message
			}
		}
	case "file":
		var data []byte
		if f, _, ferr := r.FormFile("file"); ferr == nil {
			data, err = io.ReadAll(io.LimitReader(f, maxUpload))
			f.Close()
		}
		if err == nil {
			if err = h.lic.Apply(string(data)); err == nil {
				done = "License file installed. " + h.lic.Status().Message
			}
		}
	case "request":
		name, content, rerr := h.lic.RequestFile(r.FormValue("code"))
		if rerr == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
			w.Header().Set("Cache-Control", "no-store")
			w.Write(content)
			return
		}
		err = rerr
	case "deactivate":
		if err = online.Deactivate(ctx, h.lic); err == nil {
			done = "This computer is deactivated. Use your license key to activate another computer."
		}
	default:
		err = errors.New("unknown action")
	}
	if err != nil {
		msg := "That didn't work. Please try again."
		var e *licensekit.Error
		if errors.As(err, &e) && e.Message != "" {
			msg = e.Message
		}
		h.render(w, http.StatusUnprocessableEntity, "", msg)
		return
	}
	h.render(w, http.StatusOK, done, "")
}
