// Command licensekit-cli is a minimal LicenseKit integration for a command-line app.
//
//	licensekit-cli                      show the license status
//	licensekit-cli activate KEY         activate this computer online with a license key
//	licensekit-cli apply CODE|FILE      apply a renewal code or a .license file (offline)
//	licensekit-cli request KEY FILE     save a request file for a computer without internet
//	licensekit-cli deactivate           give the license back so another computer can use the key
//
// Build it with the build setting from the Manager product page:
//
//	go build -ldflags "-X github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD" .
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/online"
)

func main() {
	lic, err := licensekit.Open("", licensekit.Options{StateDir: os.Getenv("EXAMPLE_STATE_DIR"), DeviceID: os.Getenv("EXAMPLE_DEVICE_ID")})
	if err != nil {
		fail(err)
	}
	ctx := context.Background()
	args := append(os.Args[1:], "", "")
	switch args[0] {
	case "activate":
		err = online.Activate(ctx, lic, args[1])
	case "apply":
		input := args[1]
		if b, ferr := os.ReadFile(input); ferr == nil {
			input = string(b)
		}
		err = lic.Apply(input)
	case "request":
		var content []byte
		if _, content, err = lic.RequestFile(args[1]); err == nil {
			err = os.WriteFile(args[2], content, 0o644)
			fmt.Println("Saved", args[2], "- send it to your vendor and apply the .license file you get back.")
		}
	case "deactivate":
		err = online.Deactivate(ctx, lic)
	case "":
	default:
		err = errors.New("usage: licensekit-cli [activate KEY | apply CODE|FILE | request KEY FILE | deactivate]")
	}
	if err != nil {
		fail(err)
	}
	s := lic.Status()
	fmt.Println(s.Message)
	if s.State != licensekit.Active {
		os.Exit(1)
	}
	if !s.Perpetual && s.DaysLeft <= 30 {
		fmt.Printf("Your license ends in %d days. Enter a renewal code with: licensekit-cli apply CODE\n", s.DaysLeft)
	}
	if len(s.Entitlements) > 0 {
		fmt.Println("Features:", strings.Join(s.Entitlements, ", "))
	}
}

// fail prints the customer-safe message and exits.
func fail(err error) {
	var le *licensekit.Error
	if errors.As(err, &le) {
		fmt.Fprintln(os.Stderr, le.Message)
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}
