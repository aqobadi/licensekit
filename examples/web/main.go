// Command licensekit-web shows how a web app mounts the ready-made License
// page and enforces the license. Real apps put the page behind their
// administrator sign-in.
//
//	go run -ldflags "-X github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD" . -addr 127.0.0.1:47821
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/licenseui"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:47821", "listen address (keep it on loopback)")
	flag.Parse()
	lic, err := licensekit.Open("", licensekit.Options{StateDir: os.Getenv("EXAMPLE_STATE_DIR"), DeviceID: os.Getenv("EXAMPLE_DEVICE_ID")})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	// The License page. Wrap it in your admin authentication.
	mux.Handle("/license/", http.StripPrefix("/license", licenseui.Handler(lic, licenseui.Options{Name: "Example App"})))
	// Licensed work: check the license on every operation that needs it.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if lic.Status().State != licensekit.Active {
			http.Redirect(w, r, "/license/", http.StatusSeeOther)
			return
		}
		w.Write([]byte("Licensed work happens here. Export available: "))
		if lic.Has("export") {
			w.Write([]byte("yes\n"))
		} else {
			w.Write([]byte("no\n"))
		}
	})
	log.Printf("open http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
