package pkg

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// User structures
type OnlineUser struct {
	UID int
	IP  string
}

func (u OnlineUser) String() string {
	if u.UID == 0 {
		return "{IP:REDACTED}"
	}
	return fmt.Sprintf("{UID:%d IP:REDACTED}", u.UID)
}

func (u OnlineUser) GoString() string {
	return u.String()
}

type UserInfo struct {
	Id          int    `json:"id"`
	Uuid        string `json:"uuid"`
	SpeedLimit  int    `json:"speed_limit"`
	DeviceLimit int    `json:"device_limit"`
}

func (u UserInfo) String() string {
	return fmt.Sprintf("{Id:%d Uuid:REDACTED SpeedLimit:%d DeviceLimit:%d}", u.Id, u.SpeedLimit, u.DeviceLimit)
}

func (u UserInfo) GoString() string {
	return u.String()
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

func (u UserListBody) String() string {
	return fmt.Sprintf("{Users:%d REDACTED}", len(u.Users))
}

func (u UserListBody) GoString() string {
	return u.String()
}

// UserTraffic contains incremental bytes, not lifetime counters. The panel
// applies its traffic multiplier. Replaying a report can duplicate accounting.
type UserTraffic struct {
	UID      int
	Upload   int64 // User upload: client to proxy.
	Download int64 // User download: proxy to client.
}

const maxDurationSeconds = int64(math.MaxInt64) / int64(time.Second)

func intervalSeconds(value int) time.Duration {
	if value <= 0 || int64(value) > maxDurationSeconds {
		return 0
	}
	return time.Duration(value) * time.Second
}

// IntervalToTime converts seconds, truncating fractional floats for compatibility.
// Invalid, non-positive, or overflowing values return 0; do not pass that result
// directly to a ticker. Node configs are validated separately before conversion.
func IntervalToTime(i interface{}) time.Duration {
	switch v := i.(type) {
	case int:
		return intervalSeconds(v)
	case string:
		val, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			log.Warnf("IntervalToTime: invalid string value length=%d", len(v))
			return 0
		}
		return intervalSeconds(val)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > float64(maxDurationSeconds) || v >= float64(math.MaxInt) {
			return 0
		}
		return intervalSeconds(int(v))
	}
	return 0
}
