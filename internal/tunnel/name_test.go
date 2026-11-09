package tunnel

import (
	"runtime"
	"testing"
)

func TestDeviceName(t *testing.T) {
	got, renamed := deviceName("wg0")
	if runtime.GOOS == "darwin" {
		if got != "utun" || !renamed {
			t.Fatalf("wg0 -> %s %v", got, renamed)
		}
		if n, r := deviceName("utun4"); n != "utun4" || r {
			t.Fatalf("utun4 -> %s %v", n, r)
		}
		if n, r := deviceName("utun"); n != "utun" || r {
			t.Fatalf("utun -> %s %v", n, r)
		}
		return
	}
	if got != "wg0" || renamed {
		t.Fatalf("wg0 -> %s %v", got, renamed)
	}
}
