package pkg

import (
	"fmt"
	"strings"
	"testing"
)

var benchmarkSanitizedMessage string

func BenchmarkSanitizeAPIErrorMessage(benchmark *testing.B) {
	for _, size := range []int{maxAPIErrorMessageBytes, 1024 * 1024, maxResponseBodyBytes} {
		benchmark.Run(fmt.Sprintf("bytes_%d", size), func(benchmark *testing.B) {
			body := strings.Repeat("x", size)
			benchmark.ReportAllocs()
			benchmark.ResetTimer()
			for iteration := 0; iteration < benchmark.N; iteration++ {
				benchmarkSanitizedMessage = sanitizeAPIErrorMessage(body)
			}
		})
	}
}
